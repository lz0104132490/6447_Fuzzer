Summarizing the radamsa mutation algorithm:


[2 tools called]

# Radamsa Mutation Algorithm: Summary

## Core architecture

### 1. Mutation types (pregenerated)

All mutations are hardcoded in the source code, organized by level:

**Byte-Level** (`bd`, `bf`, `bi`, `br`, `bp`, `bei`, `bed`, `ber`)
- Bit flips, byte insertions/deletions, permutations
- Works on any binary/text data

**Sequence-Level** (`sr`, `sd`)
- Repeats or deletes byte sequences
- Preserves structural elements

**Line-Level** (`ld`, `lr2`, `li`, `ls`, `lp`, `lr`, `lis`, `lrs`)
- Line operations for text files
- Detects line boundaries automatically

**Structure-Level** (`td`, `tr2`, `ts1`, `ts2`, `tr`)
- Tree/node operations for structured data
- Works on parse trees

**Specialized** (`num`, `xp`, `uw`, `ui`, `ab`, `ft`, `fn`, `fo`)
- Content-aware mutations (numbers, XML, UTF-8, ASCII)
- Format-specific transformations

## Mutation selection process

### Algorithm flow:

```1133:1154:radamsa/rad/mutations.scm
(define (mux-fuzzers fs)
   (λ (rs ll meta)
      (let loop ((ll ll)) ;; <- force up to a data node
         (cond
            ((pair? ll)
               (lets ((rs pfs (weighted-permutation rs fs))) ;; (#(score priority mutafn name) ...)
                  (let loop ((pfs pfs) (out null) (rs rs)) ;; try each in order
                     (if (null? pfs) ;; no mutation worked
                        (values (mux-fuzzers out) rs ll meta)
                        (lets
                           ((node (car pfs))
                            (mscore mpri ╯°□°╯ mname node)
                            (mfn rs mll mmeta delta
                              (╯°□°╯ rs ll meta))
                           (out ;; always remember whatever was learned
                              (cons (tuple (adjust-priority mscore delta) mpri mfn mname) out)))
                           (if (and (pair? mll) (equal? (car ll) (car mll)))
                              ;; try something else if no changes, but update state
                              (loop (cdr pfs) out rs)
                              (stderr-probe
                                 (list 'used mname) ; <- allow tracing and counting easily via stderr while testing
                                 (values (mux-fuzzers (append out (cdr pfs))) rs mll mmeta)))))))))
```

### Selection steps:

1. Weighted ranking: mutations ranked by `(score × priority) / total`
2. Sequential attempts: tries mutations in priority order
3. Success check: if output differs from input → success
4. Learning: updates priority based on delta (+2, +1, 0, -1)
5. Fallback: if first fails, tries next; continues until one succeeds

## Format detection and adaptation

### Binary vs text detection:

```52:61:radamsa/rad/mutations.scm
(define (binarish? lst)
   (let loop ((lst lst) (p 0))
      (cond
         ((eq? p 8) (stderr-probe "BINARY: NO" #false))
         ((null? lst) (stderr-probe "BINARY: NO" #false))
         ((eq? (car lst) 0) (stderr-probe "BINARY: YES" #true))
         (else
            (if (eq? 0 (fxand 128 (car lst)))
               (loop (cdr lst) (+ p 1))
               (stderr-probe "BINARY: YES" #true))))))
```

- Detects binary (null bytes, high-bit values)
- Identifies text (printable ASCII)
- Parses XML structures
- Recognizes numbers and Unicode

### Adaptive priority adjustment:

```135:153:radamsa/rad/mutations.scm
(define (sed-num rs ll meta) ;; edit a number
   (lets
      ((lst (vector->list (car ll)))
       (rs n lst (mutate-a-num rs lst 0))
       (bin? (binarish? lst))
       (lst (flush-bvecs lst (cdr ll))))
      (cond
         ((eq? n 0)
            (lets ((rs n (rand rs 10)))
               (if (eq? n 0)
                  (values sed-num rs lst meta -1)
                  (values sed-num rs lst meta 0))))
         (bin?
            (values sed-num rs lst (inc meta 'muta-num) -1))
         (else
            (values sed-num rs lst (inc meta 'muta-num) +2)))))
```

- Format-aware deltas: text data gets higher priority for text mutations
- Context-sensitive: adjusts based on detected content types

## Complete mutation workflow

### From sample to output:

```
1. INPUT PROCESSING
   Sample File → Read into Memory → Chunk into Blocks

2. FOR EACH OUTPUT (n outputs requested):
   a. FORMAT DETECTION
      - Detect binary/text/XML/structure
      - Analyze content characteristics
   
   b. MUTATION SELECTION
      - Weight all mutations by (score × priority)
      - Rank mutations probabilistically
      - Try mutations in priority order
   
   c. MUTATION APPLICATION
      - Apply selected mutation to data
      - Check if output differs from input
      - Return on first successful mutation
   
   d. LEARNING UPDATE
      - Adjust mutation priority based on success/failure
      - Update mutation scores dynamically
   
   e. OUTPUT GENERATION
      - Convert mutated chunks to output format
      - Write to file/stream

3. REPEAT for -n iterations
   - Each iteration uses different random state
   - Each iteration selects different mutation
   - Filter duplicates if checksum matching enabled
```

## Algorithm characteristics

### Strengths:

1. Adaptive learning: improves mutation selection over time
2. Format-aware: adapts to data types automatically
3. Efficient: one mutation per output, weighted selection
4. Reproducible: deterministic with seed control
5. Hierarchical: multi-level mutations from byte to structure

### Mutation selection formula:

```
Selection Probability = (Score × Priority) / Σ(All Scores × Priorities)

Where:
- Score: Dynamic (2-10), adjusted by success/failure
- Priority: User-configurable or default
- Total: Sum of all (score × priority) products
```

### Success/failure criteria:

- Success: output data ≠ input data → priority increases
- Failure: output data = input data → priority decreases
- Partial success: format mismatch (e.g., num mutation on binary) → neutral/negative

## Design principles

1. Pregenerated mutations: all mutations hardcoded, no runtime generation
2. Runtime customization: scores randomized, priorities adjusted dynamically
3. Single mutation per output: efficiency over exhaustive testing
4. Weighted probabilistic selection: higher-quality mutations more likely
5. Adaptive learning: system improves through feedback loops

## Final algorithm summary

Radamsa's mutation algorithm is an adaptive, format-aware fuzzing system that:
- Uses 30+ pregenerated mutation types across multiple abstraction levels
- Selects mutations probabilistically based on weighted scores
- Adapts to input data format automatically (binary/text/XML)
- Learns which mutations work best for specific data types
- Generates one mutated output per iteration from sample inputs
- Continuously improves through dynamic priority adjustment

This design balances efficiency (one mutation per output) with effectiveness (smart, adaptive selection) to generate high-quality test cases for finding bugs in target programs.