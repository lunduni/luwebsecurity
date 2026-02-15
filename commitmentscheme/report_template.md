# Truncated-Hash Commitment Scheme — Binding & Hiding Analysis (K = 16)

## 1. Introduction

A **commitment scheme** lets a sender commit to a value $v$ while keeping it hidden until a later “open” step.

- **Binding:** after committing, the sender should *not* be able to open the same commitment to two different values.
- **Hiding (concealing):** before opening, the receiver should *not* be able to learn $v$ from the commitment.

This report analyzes how both properties depend on the truncation length $X$.

---

## 2. Description of the Scheme

We commit to a 1-bit value $v \in \{0,1\}$ using randomness $k \in \{0,1\}^K$ (uniform), with $K=16$.

$$
\mathrm{Commit}(v,k) = \mathrm{Truncate}(h(v\|k), X) = x \in \{0,1\}^X.
$$

Here $h$ is modeled as an ideal hash (random oracle), and truncation keeps the first $X$ output bits.
Let:
- $N = 2^K$ = number of possible randomness values $k$.
- $M = 2^X$ = number of possible commitment digests.

Define the reachable digest sets:
$$
S_v = \{\mathrm{Truncate}(h(v\|k),X) : k \in \{0,1\}^K\} \subseteq \{0,1\}^X.
$$

---

## 3. Breaking Binding

### 3.1 Attack idea (sender / attacker)
A “clever” sender wants to commit in a way that allows opening to either $v=0$ or $v=1$ later.
That is, they want **two different openings** leading to the same commitment digest:

$$
\exists k_0, k_1: \mathrm{Commit}(0,k_0)=\mathrm{Commit}(1,k_1).
$$

Equivalently, the attacker needs a **cross-collision** between the two sets $S_0$ and $S_1$:
$$
S_0 \cap S_1 \neq \emptyset.
$$

This is directly tied to **collision resistance** and the **birthday paradox**: when many random samples are drawn from a space of size $M$, collisions become likely around the square-root threshold.

### 3.2 Probability of success (ideal-hash model)
In the ideal-hash model, each element of $S_0$ and $S_1$ behaves like an independent uniform draw from $\{0,1\}^X$.

- There are $N=2^K$ possible digests in each set.
- For a *fixed* pair $(k_0,k_1)$, the chance of equality is $1/M$.
- There are $N^2$ pairs.

A standard approximation (and in this setting an exact expression under independence) is:

$$
\Pr[\text{break binding}] = 1 - \left(1 - \frac{1}{M}\right)^{N^2}
= 1 - \left(1 - 2^{-X}\right)^{2^{2K}}.
$$

For large $M$, using $\log(1-z)\approx -z$ gives:

$$
\Pr[\text{break binding}] \approx 1 - \exp\left(-\frac{N^2}{M}\right)
= 1 - \exp\left(-2^{2K-X}\right).
$$

### 3.3 Trend vs X
- As $X$ decreases (smaller output space), $M=2^X$ shrinks and $N^2/M$ grows, so the probability rapidly approaches 1.
- As $X$ increases, $M$ grows and $N^2/M$ shrinks, so the probability falls quickly.
- The “birthday threshold” occurs around $M \approx N^2$ i.e. $X \approx 2K = 32$.

---

## 4. Breaking Hiding

### 4.1 Attack idea (receiver)
Given a commitment digest $x$, an unbounded receiver can try to determine whether $x$ is reachable from $v=0$ and/or from $v=1$:

- Compute the sets $S_0$ and $S_1$ (enumerate all $k \in \{0,1\}^{16}$ for each bit).
- If $x \in S_0$ but $x \notin S_1$, conclude $v=0$.
- If $x \in S_1$ but $x \notin S_0$, conclude $v=1$.
- If $x \in S_0 \cap S_1$ (or in neither), the receiver cannot uniquely determine $v$.

This attack is closely related to **preimage resistance** (finding a $k$ such that $\mathrm{Commit}(v,k)=x$) and the **uniform distribution** of hash outputs.

### 4.2 Probability of success (assignment definition)
The assignment defines:

$$
\Pr[\text{break hiding}] = \frac{\#\{x \in \{0,1\}^X : x \text{ uniquely determines } v\}}{2^X}.
$$

A digest $x$ uniquely determines $v$ iff $x \in S_0 \oplus S_1$ (exclusive-or of membership).
Let:
$$
 p = \Pr[x \in S_v].
$$

For a fixed $v$, $x$ is absent from $S_v$ only if none of the $N$ random outputs equals $x$:

$$
 p = 1 - \left(1 - \frac{1}{M}\right)^N.
$$

Assuming independence between the $v=0$ and $v=1$ images (ideal hash), the probability that *exactly one* side contains $x$ is:

$$
\Pr[x \in S_0 \oplus S_1] = 2p(1-p).
$$

So:

$$
\Pr[\text{break hiding}] = 2p(1-p),
\quad p = 1 - \left(1 - 2^{-X}\right)^{2^K}.
$$

Approximation with $\lambda = N/M = 2^{K-X}$ and $(1-1/M)^N \approx e^{-N/M}$:

$$
 p \approx 1 - e^{-\lambda},
\quad \Pr[\text{break hiding}] \approx 2(1-e^{-\lambda})e^{-\lambda}.
$$

### 4.3 Trend vs X
- If $X$ is very small, then $M$ is small and both $S_0$ and $S_1$ cover most of $\{0,1\}^X$; membership looks similar, so unique determination is rare.
- If $X$ is very large, each set occupies a tiny fraction of the space, so most digests aren’t reachable from either bit; under the assignment’s ratio metric this again pushes the ratio down.
- The ratio $2p(1-p)$ is maximized at $p=1/2$ (giving a maximum value $1/2$), which occurs when $N/M$ is around a constant (roughly $\lambda\approx\ln 2$).

---

## 5. Analysis: Tradeoff as X varies

- Increasing $X$ improves binding (fewer collisions, birthday bound decreases).
- Hiding behavior depends on how $S_0$ and $S_1$ cover the output space; the receiver’s attack is fundamentally a preimage-style search over the $k$-domain.
- With $K=16$, exhaustive search over $k$ is easy, so truncation choice dominates the tradeoff.

---

## Appendix: Generating the plots

This repo includes a helper script:

- `commitmentscheme/commitment_probabilities.py`

It writes:
- `commitmentscheme/out/probabilities.csv`
- `commitmentscheme/out/probabilities.png` (combined; if matplotlib is installed)
- `commitmentscheme/out/probabilities_binding.png` (binding-only; if matplotlib is installed)
- `commitmentscheme/out/probabilities_hiding.png` (hiding-only; if matplotlib is installed)

Example run:

```bash
python commitmentscheme/commitment_probabilities.py --min-x 4 --max-x 48 --outdir commitmentscheme/out
```
