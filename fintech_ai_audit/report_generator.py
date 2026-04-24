import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from pyrit.memory import CentralMemory
from pyrit.models import MessagePiece, Score


def _summarize_score(score: Score) -> dict[str, Any]:
    """Build a compact dict from a single Score object."""
    return {
        "score_id": str(score.id),
        "message_piece_id": str(score.message_piece_id),
        "score_type": score.score_type,
        "score_value": score.score_value,
        "score_value_description": score.score_value_description,
        "score_category": score.score_category,
        "score_rationale": score.score_rationale[:300] if score.score_rationale else "",
        "scorer": score.scorer_class_identifier.class_name if score.scorer_class_identifier else "unknown",
    }


def _build_conversations(
    *,
    all_pieces: list[MessagePiece],
    scores: list[Score],
) -> list[dict[str, Any]]:
    """Group message pieces into conversations, pairing user-assistant exchanges as turns."""
    score_by_piece: dict[str, Score] = {}
    for s in scores:
        score_by_piece[str(s.message_piece_id)] = s

    conversations_map: dict[str, list[MessagePiece]] = {}
    for piece in all_pieces:
        cid = str(piece.conversation_id)
        conversations_map.setdefault(cid, []).append(piece)

    conversations: list[dict[str, Any]] = []
    for cid, pieces in conversations_map.items():
        sorted_pieces = sorted(pieces, key=lambda p: p.sequence)

        # Extract the original objective (first user message)
        objective = ""
        for p in sorted_pieces:
            if p.role == "user":
                objective = p.converted_value or p.original_value or ""
                break

        # Pair consecutive user-assistant messages into numbered turns
        paired_turns: list[dict[str, Any]] = []
        turn_number = 0
        i = 0
        while i < len(sorted_pieces):
            p = sorted_pieces[i]
            if p.role == "user":
                turn_number += 1
                user_content = p.converted_value or p.original_value or ""
                assistant_content = ""
                score_value = None
                score_rationale = ""
                # Look ahead for the paired assistant response
                if i + 1 < len(sorted_pieces) and sorted_pieces[i + 1].role == "assistant":
                    ap = sorted_pieces[i + 1]
                    assistant_content = ap.converted_value or ap.original_value or ""
                    piece_score = score_by_piece.get(str(ap.id))
                    if piece_score:
                        score_value = piece_score.score_value
                        score_rationale = (
                            piece_score.score_rationale[:300] if piece_score.score_rationale else ""
                        )
                    i += 2
                else:
                    i += 1
                paired_turns.append({
                    "turn_number": turn_number,
                    "prompt": user_content,
                    "response": assistant_content,
                    "score_value": score_value,
                    "score_rationale": score_rationale,
                })
            else:
                i += 1

        conversations.append({
            "conversation_id": cid,
            "objective": objective,
            "turns": paired_turns,
            "total_turns": turn_number,
        })
    return conversations


def _build_threat_section(
    *,
    threat_name: str,
    owasp: str,
    mitre: str,
    attack_strategy: str,
    dataset_names: list[str],
    max_prompts: int | None,
    scores: list[Score],
    all_pieces: list[MessagePiece],
) -> dict[str, Any]:
    """Assemble the per-threat section of the report."""

    true_false_scores = [s for s in scores if s.score_type == "true_false"]
    float_scores = [s for s in scores if s.score_type == "float_scale"]

    successful_attacks = sum(1 for s in true_false_scores if s.score_value.lower() == "true")
    failed_attacks = sum(1 for s in true_false_scores if s.score_value.lower() == "false")

    success_rate = round(successful_attacks / (successful_attacks + failed_attacks) * 100, 2) if (successful_attacks + failed_attacks) else 0.0
    refusal_rate = round(failed_attacks / (successful_attacks + failed_attacks) * 100, 2) if (successful_attacks + failed_attacks) else 0.0

    avg_float = (
        round(sum(float(s.score_value) for s in float_scores) / len(float_scores), 4)
        if float_scores
        else None
    )

    # Build conversations and compute turn count from actual data
    conversations = _build_conversations(
        all_pieces=all_pieces,
        scores=scores,
    )
    turn_count = max((c["total_turns"] for c in conversations), default=1)
    total_prompts_to_llm = sum(1 for p in all_pieces if p.role == "user")

    section: dict[str, Any] = {
        "threat_name": threat_name,
        "attack_configuration": {
            "attack_type": threat_name,
            "attack_strategy": attack_strategy,
            "datasets_used": dataset_names,
        },
        "framework_mapping": {
            "owasp": owasp,
            "mitre_atlas": mitre,
        },
        "statistics": {
            "total_prompts_to_llm": total_prompts_to_llm,
            "max_prompts": max_prompts if max_prompts is not None else "unlimited",
            "turn_count": turn_count,
            "successful_attacks": successful_attacks,
            "failed_attacks": failed_attacks,
            "attack_success_rate_pct": success_rate,
            "refusal_rate_pct": refusal_rate,
        },
    }

    if avg_float is not None:
        section["statistics"]["average_float_score"] = avg_float

    # Include the top 10 successful attack examples for analyst review
    successful_samples = [
        _summarize_score(s) for s in true_false_scores if s.score_value.lower() == "true"
    ][:10]
    section["sample_successful_attacks"] = successful_samples

    section["conversations"] = conversations

    return section


_HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ meta.report_title }}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 2rem; color: #222; }
  h1 { color: #1a1a2e; }
  h2 { color: #16213e; border-bottom: 2px solid #0f3460; padding-bottom: .3rem; }
  h3 { color: #0f3460; }
  h4 { color: #1a237e; margin-top: 1rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #ccc; padding: .5rem .75rem; text-align: left; }
  th { background: #0f3460; color: #fff; }
  tr:nth-child(even) { background: #f4f4f4; }
  .sample { background: #fff3e0; padding: .75rem; margin: .5rem 0; border-left: 4px solid #e65100; }
  .config-box { background: #ede7f6; border: 1px solid #6a1b9a; border-radius: 6px; padding: .75rem 1rem; margin: .75rem 0; }
  .config-box strong { color: #4a148c; }
  .config-label { display: inline-block; background: #6a1b9a; color: #fff; padding: .15rem .5rem; border-radius: 3px; font-size: .85em; margin-right: .4rem; }
  .framework-box { background: #e3f2fd; border: 1px solid #1565c0; border-radius: 6px; padding: .75rem 1rem; margin: .75rem 0; }
  .framework-box strong { color: #0d47a1; }
  .framework-label { display: inline-block; background: #0d47a1; color: #fff; padding: .15rem .5rem; border-radius: 3px; font-size: .85em; margin-right: .4rem; }
  .prompt-block { border: 1px solid #ddd; border-radius: 6px; margin: 1rem 0; padding: 0; background: #fafafa; overflow: hidden; }
  .prompt-header { background: #1565c0; color: #fff; padding: .5rem .75rem; font-weight: bold; font-size: .95em; }
  .prompt-objective { background: #e8eaf6; padding: .5rem .75rem; font-size: .9em; border-bottom: 1px solid #ddd; }
  .turn-block { padding: .5rem .75rem; border-bottom: 1px solid #eee; }
  .turn-block:last-child { border-bottom: none; }
  .turn-label { font-weight: bold; font-size: .85em; color: #0d47a1; margin-bottom: .3rem; }
  .turn-prompt { background: #e3f2fd; border-left: 3px solid #1565c0; padding: .4rem .6rem; margin: .3rem 0; border-radius: 4px; }
  .turn-response { background: #f3e5f5; border-left: 3px solid #6a1b9a; padding: .4rem .6rem; margin: .3rem 0; border-radius: 4px; }
  .turn-prompt-label { font-weight: bold; font-size: .8em; text-transform: uppercase; color: #1565c0; }
  .turn-response-label { font-weight: bold; font-size: .8em; text-transform: uppercase; color: #6a1b9a; }
  .turn-score { font-size: .85em; color: #c62828; margin-top: .3rem; padding: .2rem .4rem; background: #ffebee; border-radius: 3px; }
</style>
</head>
<body>
<h1>{{ meta.report_title }}</h1>
<p><strong>Run ID:</strong> {{ meta.run_id }}<br>
<strong>Generated:</strong> {{ meta.generated_at }}<br>
<strong>Target Model:</strong> {{ meta.target_model }}<br>
<strong>Judge Model:</strong> {{ meta.judge_model }}</p>

<h2>Executive Summary</h2>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  <tr><td>Total Prompts to LLM</td><td>{{ summary.total_prompts_to_llm }}</td></tr>
  <tr><td>Max Prompts (configured limit)</td><td>{{ summary.max_prompts }}</td></tr>
  <tr><td>Successful Attacks</td><td>{{ summary.total_successful_attacks }}</td></tr>
  <tr><td>Attack Success Rate</td><td>{{ summary.overall_attack_success_rate_pct }}%</td></tr>
</table>

{% for threat in threats %}
<h2>{{ threat.threat_name }}</h2>

<h3>Attack Configuration</h3>
<div class="config-box">
  <span class="config-label">Attack Type</span> {{ threat.attack_configuration.attack_type }}<br>
  <span class="config-label">Strategy</span> {{ threat.attack_configuration.attack_strategy }}<br>
  <span class="config-label">Datasets Used</span> {{ threat.attack_configuration.datasets_used | join(', ') }}
</div>

<h3>Security Framework Mapping</h3>
<div class="framework-box">
  <span class="framework-label">OWASP</span> {{ threat.framework_mapping.owasp }}<br>
  <span class="framework-label">MITRE ATLAS</span> {{ threat.framework_mapping.mitre_atlas }}
</div>

<h3>Results</h3>
<table>
  <tr><th>Metric</th><th>Value</th></tr>
  {% for key, val in threat.statistics.items() %}
  <tr><td>{{ key }}</td><td>{{ val }}</td></tr>
  {% endfor %}
</table>
{% if threat.sample_successful_attacks %}
<h3>Sample Successful Attacks (up to 10)</h3>
{% for sample in threat.sample_successful_attacks %}
<div class="sample">
  <strong>Score ID:</strong> {{ sample.score_id }}<br>
  <strong>Category:</strong> {{ sample.score_category }}<br>
  <strong>Rationale:</strong> {{ sample.score_rationale }}
</div>
{% endfor %}
{% endif %}
{% if threat.conversations %}
<h3>Prompt &amp; Response History</h3>
{% for conv in threat.conversations %}
<div class="prompt-block">
  <div class="prompt-header">Prompt {{ loop.index }} ({{ conv.total_turns }} turn{{ 's' if conv.total_turns != 1 else '' }})</div>
  <div class="prompt-objective"><strong>Objective:</strong> {{ conv.objective[:500] }}</div>
  {% for turn in conv.turns %}
  <div class="turn-block">
    <div class="turn-label">Turn {{ turn.turn_number }}</div>
    <div class="turn-prompt">
      <span class="turn-prompt-label">Prompt:</span> {{ turn.prompt[:500] }}
    </div>
    {% if turn.response %}
    <div class="turn-response">
      <span class="turn-response-label">Response:</span> {{ turn.response[:500] }}
    </div>
    {% endif %}
    {% if turn.score_value %}
    <div class="turn-score">Score: {{ turn.score_value }} &mdash; {{ turn.score_rationale }}</div>
    {% endif %}
  </div>
  {% endfor %}
</div>
{% endfor %}
{% endif %}
{% endfor %}
</body>
</html>
""")


def _render_html(report: dict[str, Any], output_path: Path) -> None:
    """Render the report dict as an HTML file."""
    html = _HTML_TEMPLATE.render(
        meta=report["report_metadata"],
        summary=report["executive_summary"],
        threats=report["threat_results"],
    )
    output_path.write_text(html, encoding="utf-8")


def _render_pdf(report: dict[str, Any], output_path: Path) -> None:
    """Render the report dict as a PDF file using reportlab."""
    doc = SimpleDocTemplate(str(output_path), pagesize=letter)
    styles = getSampleStyleSheet()
    story: list[Any] = []

    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=12)
    heading_style = ParagraphStyle("ReportH2", parent=styles["Heading2"], spaceAfter=6)
    normal_style = styles["Normal"]

    meta = report["report_metadata"]
    summary = report["executive_summary"]

    story.append(Paragraph(meta["report_title"], title_style))
    story.append(Paragraph(
        f"Run ID: {meta['run_id']}<br/>"
        f"Generated: {meta['generated_at']}<br/>"
        f"Target Model: {meta['target_model']}<br/>"
        f"Judge Model: {meta['judge_model']}",
        normal_style,
    ))
    story.append(Spacer(1, 0.3 * inch))

    # Executive summary table
    story.append(Paragraph("Executive Summary", heading_style))
    summary_data = [["Metric", "Value"]] + [
        [k, str(v)] for k, v in summary.items()
    ]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f4")]),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3 * inch))

    # Styles for attack config and framework highlights
    config_style = ParagraphStyle(
        "Config", parent=normal_style, fontSize=9,
        backColor=colors.HexColor("#ede7f6"), borderColor=colors.HexColor("#6a1b9a"),
        borderWidth=1, borderPadding=6, spaceAfter=6,
    )
    framework_style = ParagraphStyle(
        "Framework", parent=normal_style, fontSize=9,
        backColor=colors.HexColor("#e3f2fd"), borderColor=colors.HexColor("#1565c0"),
        borderWidth=1, borderPadding=6, spaceAfter=6,
    )
    turn_prompt_style = ParagraphStyle(
        "TurnPrompt", parent=normal_style, fontSize=8, leftIndent=12,
        backColor=colors.HexColor("#e3f2fd"), spaceAfter=2,
    )
    turn_response_style = ParagraphStyle(
        "TurnResponse", parent=normal_style, fontSize=8, leftIndent=12,
        backColor=colors.HexColor("#f3e5f5"), spaceAfter=2,
    )
    score_style = ParagraphStyle(
        "TurnScore", parent=normal_style, fontSize=8, leftIndent=12,
        textColor=colors.HexColor("#c62828"), spaceAfter=4,
    )

    # Per-threat sections
    for threat in report["threat_results"]:
        story.append(Paragraph(threat["threat_name"], heading_style))

        # Attack Configuration section
        attack_config = threat["attack_configuration"]
        story.append(Paragraph("Attack Configuration", styles["Heading3"]))
        story.append(Paragraph(
            f"<b>Attack Type:</b> {attack_config['attack_type']}<br/>"
            f"<b>Strategy:</b> {attack_config['attack_strategy']}<br/>"
            f"<b>Datasets Used:</b> {', '.join(attack_config['datasets_used'])}",
            config_style,
        ))
        story.append(Spacer(1, 0.1 * inch))

        # Security Framework Mapping section
        fw = threat["framework_mapping"]
        story.append(Paragraph("Security Framework Mapping", styles["Heading3"]))
        story.append(Paragraph(
            f"<b>OWASP:</b> {fw['owasp']}<br/>"
            f"<b>MITRE ATLAS:</b> {fw['mitre_atlas']}",
            framework_style,
        ))
        story.append(Spacer(1, 0.15 * inch))

        # Results table
        story.append(Paragraph("Results", styles["Heading3"]))
        stats_data = [["Metric", "Value"]] + [
            [k, str(v)] for k, v in threat["statistics"].items()
        ]
        stats_table = Table(stats_data, hAlign="LEFT")
        stats_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f4f4")]),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        story.append(stats_table)

        samples = threat.get("sample_successful_attacks", [])
        if samples:
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph("Sample Successful Attacks", styles["Heading3"]))
            for sample in samples:
                story.append(Paragraph(
                    f"<b>Score ID:</b> {sample['score_id']}<br/>"
                    f"<b>Category:</b> {sample['score_category']}<br/>"
                    f"<b>Rationale:</b> {sample['score_rationale']}",
                    normal_style,
                ))
                story.append(Spacer(1, 0.1 * inch))

        # Prompt & Response History
        conversations = threat.get("conversations", [])
        if conversations:
            story.append(Spacer(1, 0.1 * inch))
            story.append(Paragraph("Prompt &amp; Response History", styles["Heading3"]))
            for idx, conv in enumerate(conversations, 1):
                total_turns = conv.get("total_turns", len(conv["turns"]))
                story.append(Paragraph(
                    f"<b>Prompt {idx}</b> ({total_turns} turn{'s' if total_turns != 1 else ''})",
                    normal_style,
                ))
                objective = conv.get("objective", "")[:500]
                if objective:
                    story.append(Paragraph(f"<b>Objective:</b> {objective}", normal_style))
                for turn in conv["turns"]:
                    story.append(Paragraph(
                        f"<b>Turn {turn['turn_number']} — Prompt:</b> {turn['prompt'][:500]}",
                        turn_prompt_style,
                    ))
                    if turn.get("response"):
                        story.append(Paragraph(
                            f"<b>Turn {turn['turn_number']} — Response:</b> {turn['response'][:500]}",
                            turn_response_style,
                        ))
                    if turn.get("score_value"):
                        story.append(Paragraph(
                            f"Score: {turn['score_value']} — {turn.get('score_rationale', '')}",
                            score_style,
                        ))
                story.append(Spacer(1, 0.1 * inch))

        story.append(Spacer(1, 0.3 * inch))

    doc.build(story)


def generate_report(
    *,
    run_id: str,
    threat_classes: list[type],
    output_dir: str | Path = ".",
    formats: list[str] | None = None,
    max_prompts: int | None = None,
) -> list[Path]:
    """
    Query PyRIT memory for all prompts and scores in a run,
    then write reports in the requested formats.

    Args:
        run_id (str): The UUID of the audit run.
        threat_classes (list[type]): The scenario classes that were executed.
        output_dir (str | Path): Directory to write the report files. Defaults to cwd.
        formats (list[str] | None): Output formats to generate. Supports "json", "html", "pdf".
            Defaults to ["json"] when None.
        max_prompts (int | None): The configured max-prompts limit for the run. Defaults to None.

    Returns:
        list[Path]: The paths to all generated report files.
    """
    if formats is None:
        formats = ["json"]

    valid_formats = {"json", "html", "pdf"}
    invalid = set(formats) - valid_formats
    if invalid:
        raise ValueError(f"Unsupported report format(s): {invalid}. Valid options: {valid_formats}")
    memory = CentralMemory.get_memory_instance()
    now = datetime.now(tz=timezone.utc)

    target_model = os.environ.get("TARGET_LLM_MODEL", "unknown")
    judge_model = os.environ.get("JUDGE_LLM_MODEL", "unknown")
    report_title = f"AI Red Teaming Report using PyRIT on {target_model}"

    threat_sections: list[dict[str, Any]] = []
    global_total_prompts_to_llm = 0
    global_total_successful = 0
    global_total_scored = 0

    for threat_class in threat_classes:
        scenario = threat_class()

        # Retrieve all message pieces for this threat within the run
        all_pieces = memory.get_message_pieces(
            labels={"run_id": run_id, "threat": scenario.threat_name}
        )

        user_pieces = [p for p in all_pieces if p.role == "user"]
        assistant_pieces = [p for p in all_pieces if p.role == "assistant"]

        # Retrieve scores for assistant responses
        assistant_ids = [str(p.id) for p in assistant_pieces]
        scores: list[Score] = []
        if assistant_ids:
            scores = list(
                memory.get_prompt_scores(
                    labels={"run_id": run_id, "threat": scenario.threat_name},
                    role="assistant",
                )
            )

        section = _build_threat_section(
            threat_name=scenario.threat_name,
            owasp=scenario.owasp_mapping,
            mitre=scenario.mitre_atlas_mapping,
            attack_strategy=scenario.attack_strategy,
            dataset_names=scenario.dataset_names,
            max_prompts=max_prompts,
            scores=scores,
            all_pieces=list(all_pieces),
        )
        threat_sections.append(section)

        # Accumulate globals
        global_total_prompts_to_llm += len(user_pieces)
        tf_scores = [s for s in scores if s.score_type == "true_false"]
        global_total_scored += len(tf_scores)
        global_total_successful += sum(1 for s in tf_scores if s.score_value.lower() == "true")

    global_success_rate = (
        round(global_total_successful / global_total_scored * 100, 2) if global_total_scored else 0.0
    )

    report: dict[str, Any] = {
        "report_metadata": {
            "report_title": report_title,
            "run_id": run_id,
            "generated_at": now.isoformat(),
            "target_model": target_model,
            "judge_model": judge_model,
            "threats_executed": len(threat_sections),
        },
        "executive_summary": {
            "total_prompts_to_llm": global_total_prompts_to_llm,
            "max_prompts": max_prompts if max_prompts is not None else "unlimited",
            "total_successful_attacks": global_total_successful,
            "overall_attack_success_rate_pct": global_success_rate,
        },
        "threat_results": threat_sections,
    }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"red_team_report_{run_id}"

    generated_paths: list[Path] = []

    if "json" in formats:
        json_path = output_dir / f"{base_name}.json"
        json_path.write_text(json.dumps(report, indent=2, default=str))
        generated_paths.append(json_path)
        print(f"\n[REPORT] JSON report written to: {json_path}")

    if "html" in formats:
        html_path = output_dir / f"{base_name}.html"
        _render_html(report, html_path)
        generated_paths.append(html_path)
        print(f"[REPORT] HTML report written to: {html_path}")

    if "pdf" in formats:
        pdf_path = output_dir / f"{base_name}.pdf"
        _render_pdf(report, pdf_path)
        generated_paths.append(pdf_path)
        print(f"[REPORT] PDF report written to: {pdf_path}")

    return generated_paths
