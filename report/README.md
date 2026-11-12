# Report (LaTeX)

Full mid-term report, ready for Overleaf. It is self-contained: figures are in
`figures/`, result tables are embedded, and the architecture/sequence diagrams
are drawn with TikZ, so no external tools are needed to build it.

## Build on Overleaf
1. Zip this `report/` folder and upload it as a new Overleaf project
   (or drag the files in).
2. Menu → Compiler: **pdfLaTeX**. Main document: **main.tex**.
3. Recompile (Overleaf runs BibTeX automatically for the references).

## Before submitting — must do
- `members.tex`: fill in the real names, student IDs, lecturer, group number.
- `chapters/appendix.tex`: fill in the per-member contribution table.
- `refs.bib`: verify every entry against the original (DOI). In particular read
  the AlZomai (2008) and Haupert & Gabert (2019) figures from the originals, and
  check whether Decision 2345/QD-NHNN is still in force before citing it.

## Keeping figures/tables in sync with the data
Every number comes from `../results/` (produced by `make eval`). The scenario and
goal tables are embedded copies of `results/scenarios.tex` and
`results/goals.tex`; if `make eval` is re-run and numbers change, refresh the
embedded tables and re-copy the figures:
```bash
cp ../results/screens/*.png ../results/bench.pdf ../results/bruteforce.pdf figures/
```
