from pyrit.memory import SQLiteMemory
from pyrit.memory.memory_models import Base


def main() -> None:
    memory = SQLiteMemory()

    print(f"Database: {memory.db_path}\n")

    models = memory.get_all_table_models()

    print(f"{'Table Name':<30} {'Row Count':>10}")
    print("-" * 42)

    for model in sorted(models, key=lambda m: m.__tablename__):
        entries = memory._query_entries(model)
        print(f"{model.__tablename__:<30} {len(entries):>10}")

    print()

    # Show schema details
    memory.print_schema()


main()
