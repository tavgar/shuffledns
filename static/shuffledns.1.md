# SHUFFLEDNS(1)

## NAME
shuffledns \- fast DNS enumerator with wildcard handling

## SYNOPSIS
**shuffledns** [OPTIONS]

## DESCRIPTION
This release introduces baseline wildcard detection. Use `--wildcard-baseline` and
`--wildcard-threshold` to tune detection accuracy. Baselines can be saved with
`--wildcard-save` and reused via `--wildcard-load`.
