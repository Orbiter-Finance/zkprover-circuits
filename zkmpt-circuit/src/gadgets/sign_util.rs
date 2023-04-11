use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    halo2curves::FieldExt,
    plonk::{Challenge, ConstraintSystem, Expression, FirstPhase, SecondPhase, VirtualCells},
};

/// Returns the random linear combination of the inputs.
/// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
pub(crate) mod rlc {
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};
    use std::ops::{Add, Mul};

    use super::Expr;

    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(expressions: &[E], randomness: E) -> Expression<F> {
        if !expressions.is_empty() {
            generic(expressions.iter().map(|e| e.expr()), randomness.expr())
        } else {
            0.expr()
        }
    }

    pub(crate) fn value<'a, F: FieldExt, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let values = values
            .into_iter()
            .map(|v| F::from(*v as u64))
            .collect::<Vec<F>>();
        if !values.is_empty() {
            generic(values, randomness)
        } else {
            F::zero()
        }
    }

    fn generic<V, I>(values: I, randomness: V) -> V
    where
        I: IntoIterator<Item = V>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
        V: Clone + Add<Output = V> + Mul<Output = V>,
    {
        let mut values = values.into_iter().rev();
        let init = values.next().expect("values should not be empty");

        values.fold(init, |acc, value| acc * randomness.clone() + value)
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    use super::Expr;

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: FieldExt, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: FieldExt>(b: F) -> F {
        F::one() - b
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: FieldExt> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

impl<F: FieldExt> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: FieldExt> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: FieldExt> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            F::from(self.unsigned_abs() as u64)
                * if self.is_negative() {
                    -F::one()
                } else {
                    F::one()
                },
        )
    }
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: halo2_proofs::arithmetic::FieldExt> Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: halo2_proofs::arithmetic::FieldExt> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);

pub(crate) fn query_expression<F: FieldExt, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

/// All challenges used in `SuperCircuit`.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    evm_word: T,
    keccak_input: T,
    lookup_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        #[cfg(any(feature = "test", test, feature = "test-circuits"))]
        let _dummy_cols = [
            meta.advice_column(),
            meta.advice_column_in(SecondPhase),
            meta.advice_column_in(halo2_proofs::plonk::ThirdPhase),
        ];

        Self {
            evm_word: meta.challenge_usable_after(FirstPhase),
            keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [evm_word, keccak_input, lookup_input] = query_expression(meta, |meta| {
            [self.evm_word, self.keccak_input, self.lookup_input]
                .map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: layouter.get_challenge(self.evm_word),
            keccak_input: layouter.get_challenge(self.keccak_input),
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    /// Returns challenge of `evm_word`.
    pub fn evm_word(&self) -> T {
        self.evm_word.clone()
    }

    /// Returns challenge of `keccak_input`.
    pub fn keccak_input(&self) -> T {
        self.keccak_input.clone()
    }

    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 3] {
        [&self.evm_word, &self.keccak_input, &self.lookup_input]
    }

    pub(crate) fn mock(evm_word: T, keccak_input: T, lookup_input: T) -> Self {
        Self {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }

    /// Returns powers of randomness for word RLC encoding
    pub fn evm_word_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.evm_word.clone())
    }

    /// Returns powers of randomness for keccak circuit's input
    pub fn keccak_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.keccak_input.clone())
    }

    /// Returns powers of randomness for lookups
    pub fn lookup_input_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.lookup_input.clone())
    }
}
