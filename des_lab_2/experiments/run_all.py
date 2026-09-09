"""
Runs the three Part I experiments and leaves their results in `results/`.

    python -m experiments.run_all
"""

import importlib

EXPERIMENTS = (
    ("Ejercicio 4 — ECB frente a CBC", "experiments.exp_ecb_vs_cbc"),
    ("Ejercicio 5 — Efecto del IV", "experiments.exp_iv_effect"),
    ("Ejercicio 6 — Propagación de error", "experiments.exp_error_propagation"),
)


def main() -> None:
    from console import use_utf8_stdout

    use_utf8_stdout()
    for title, module_name in EXPERIMENTS:
        print(f"\n\n########## {title} ##########\n")
        importlib.import_module(module_name).run()


if __name__ == "__main__":
    main()
