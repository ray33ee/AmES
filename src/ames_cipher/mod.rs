
pub mod ames {
    use galois_2p8::{GeneralField, IrreducablePolynomial, PrimitivePolynomialField};
    use galois_2p8::Field;

    use std::fmt;

    use rand_chacha::{ChaChaRng, rand_core::SeedableRng};

    use rand::seq::SliceRandom;
    use rand::distributions::{Uniform, Distribution};
    use rand::Rng;

    use cipher::block::{BlockCipher, NewBlockCipher, Key};
    use cipher::consts::{U32, U16, U1};
    use cipher::block::Block;

    use num_derive::{ToPrimitive, FromPrimitive};
    use num_traits::FromPrimitive;

    pub const STATE_SIZE: usize = 16;
    pub const ROUND_COUNT_RANGE: std::ops::RangeInclusive<u32> = 15..=20;

    const ROW_SIZE: usize = 4;



    //Number of possible actions. Currently 4 (XOR, Scramble, Linear and SBox)
    // If more actions are added, this number must be updated accordingly
    const ACTION_COUNT: u32 = 4;

    #[derive(Debug, Clone, Copy, ToPrimitive, FromPrimitive)]
    enum Action {
        XOR,
        Scramble,
        Linear,
        SBox
    }

    trait SBox {
        fn forward(&self, byte: u8) -> u8;

        fn reverse(&self, byte: u8) -> u8;

        fn new<R: Rng + ?Sized>(rng: & mut R) -> Self;

        fn is_valid(&self) -> bool {
            for byte in 0..=255 {
                //Sbox is not valid if it
                // - contains fixed points (i.e. s(a) = a)
                // - contains opposite points (i.e. s(a) = complement(a))
                // - is not invertable (i.e. s^{-1}(s(a)) != a
                if self.forward(byte) == byte ||
                    self.forward(byte) == !byte ||
                    self.reverse(self.forward(byte)) != byte {
                    return false;
                }
            }
            true
        }
    }

    struct RandomRijndaelSBox {
        _field: GeneralField,
        _mult: u8,
        _add: u8
    }

    impl SBox for RandomRijndaelSBox {

        fn forward(&self, byte: u8) -> u8 {
            let mul_inv = if byte == 0 {
                0
            }
            else {
                self._field.div(1, byte)
            };

            self._field.mult(self._mult, mul_inv) ^ self._add
        }

        fn reverse(&self, byte: u8) -> u8 {
            let inv = self._field.div(byte ^ self._add, self._mult);

            if inv == 0 {
                0
            }
            else {
                self._field.div(1, inv)
            }
        }

        fn new<R: Rng + ?Sized>(rng: & mut R) -> Self {
            let mult = rng.gen_range(1..=255);
            let add = rng.gen_range(1..=255);

            RandomRijndaelSBox {
                _field: GeneralField::new(IrreducablePolynomial::Poly84310),
                _mult: mult,
                _add: add
            }
        }

    }

    struct ArraySbox {
        _forward: Vec<u8>,
        _reverse: Vec<u8>
    }

    impl SBox for ArraySbox {

        fn forward(&self, byte: u8) -> u8 {
            self._forward[byte as usize]
        }

        fn reverse(&self, byte: u8) -> u8 {
            self._reverse[byte as usize]
        }

        fn new<R: Rng + ?Sized>(rng: & mut R) -> Self {
            let mut forward: Vec<_> = (0..=255).into_iter().collect();

            forward.shuffle(rng);

            let mut reverse = vec![0; 256];

            for (i, map_element) in forward.iter().enumerate() {
                reverse[*map_element as usize] = i as u8;
            }

            ArraySbox {
                _forward: forward,
                _reverse: reverse
            }
        }

    }

    struct State<'a, 'b> {
        _field: & 'a PrimitivePolynomialField,
        _array: & 'b mut [u8]
    }

    impl fmt::Debug for State<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("State")
                .field("_array", &self._array)
                .field("_field", &IrreducablePolynomial::Poly84310)
                .finish()
        }
    }

    impl<'a, 'b> State<'a, 'b> {
        fn new(field: & 'a PrimitivePolynomialField, array: & 'b mut [u8]) -> Self {
            State {
                _field: field,
                _array: array
            }
        }

        fn xor(& mut self, key: & [u8]) {
            for (state_byte, key_byte) in self._array.iter_mut().zip(key.iter()) {
                *state_byte = self._field.add(*key_byte, *state_byte);
            }
        }

        fn scramble(& mut self, permutation: & [u8; STATE_SIZE]) {
            let mut tmp = [0; STATE_SIZE];

            for (tmp_byte, permuter) in tmp.iter_mut().zip(permutation.iter()) {
                *tmp_byte = self._array[*permuter as usize]
            }

            self._array.clone_from_slice(&tmp);
        }

        fn linear(& mut self, polynomial: & [u8; ROW_SIZE]) {
            for i in 0..(STATE_SIZE / ROW_SIZE) {
                let row = & mut self._array[i*ROW_SIZE..i*ROW_SIZE+ROW_SIZE];

                let mut new_row = [0u8; ROW_SIZE];

                for (j, new_row_element) in new_row.iter_mut().enumerate() {

                    for (k, row_element) in row.iter().enumerate() {
                        //Perform some dirty modular arithmetic to shift each row
                        let polynomial_element = polynomial[(k + ROW_SIZE - j) % ROW_SIZE];
                        //Perform matrix multiplication by multiplying each element and adding them up
                        *new_row_element = self._field.add(*new_row_element, self._field.mult(polynomial_element, *row_element))
                    }
                }

                row.clone_from_slice(&new_row);
            }
        }

        fn remap<F>(& mut self, sbox: &F)
            where F: Fn(u8) -> u8
        {
            for byte in self._array.iter_mut() {
                *byte = sbox(*byte)
            }
        }

        fn transform<F>(& mut self,
                        sequence: & [Action],
                        key: & [u8],
                        polynomial: & [u8; ROW_SIZE],
                        permutation: & [u8; STATE_SIZE],
                        sbox: F)
            where F: Fn(u8) -> u8
        {

            for action in sequence.iter() {
                match action {
                    Action::XOR => {
                        self.xor(key);
                    },
                    Action::Linear => {
                        self.linear(polynomial);
                    },
                    Action::SBox => {
                        self.remap(&sbox);
                    },
                    Action::Scramble => {
                        self.scramble(permutation);
                    }
                }
            }
        }
    }

    fn is_valid_permutation(permutation: & [u8; STATE_SIZE]) -> bool {
        //Make sure the permutation maps element n to element m such that n != m
        for (i, element) in permutation.iter().enumerate() {
            if *element == i as u8 {
                return false;
            }
        }
        true
    }

    fn is_valid_polynomial(field: & PrimitivePolynomialField, polynomial: & [u8; ROW_SIZE]) -> bool {
        //Make sure the determinant (of the circulant matrix generated by the polynomial) is non-zero
        determinant(field, polynomial) != 0
    }

    fn invert_map(map: & [u8]) -> [u8; STATE_SIZE] {
        let mut inverted = [0; STATE_SIZE];

        for (i, map_element) in map.iter().enumerate() {
            inverted[*map_element as usize] = i as u8;
        }

        inverted
    }

    // Returns the determinant of the 4x4 circulant matrix generated by 'polynomial'
    fn determinant(field: & PrimitivePolynomialField, polynomial: & [u8; ROW_SIZE]) -> u8 {

        let alpha = polynomial[0];
        let beta = polynomial[1];
        let gamma = polynomial[2];
        let delta = polynomial[3];

        field.mult(field.mult(alpha, alpha), field.mult(alpha, alpha)) ^ field.mult(field.mult(alpha, beta), field.mult(beta, gamma)) ^  field.mult(field.mult(alpha, gamma), field.mult(delta, delta)) ^

            field.mult(field.mult(beta, delta), field.mult(beta, delta)) ^   field.mult(field.mult(beta, beta), field.mult(gamma, alpha)) ^  field.mult(field.mult(beta, gamma), field.mult(alpha, beta)) ^

            field.mult(field.mult(gamma, delta), field.mult(delta, alpha)) ^ field.mult(field.mult(gamma, alpha), field.mult(beta, beta)) ^  field.mult(field.mult(gamma, gamma), field.mult(gamma, gamma)) ^

            field.mult(field.mult(delta, delta), field.mult(alpha, gamma)) ^ field.mult(field.mult(delta, alpha), field.mult(gamma, delta)) ^field.mult(field.mult(delta, beta), field.mult(delta, beta)) ^

            field.mult(field.mult(alpha, alpha), field.mult(beta, delta)) ^  field.mult(field.mult(alpha, beta), field.mult(delta, alpha)) ^ field.mult(field.mult(alpha, gamma), field.mult(alpha, gamma)) ^

            field.mult(field.mult(beta, delta), field.mult(alpha, alpha)) ^  field.mult(field.mult(beta, beta), field.mult(beta, beta)) ^    field.mult(field.mult(beta, gamma), field.mult(gamma, delta)) ^

            field.mult(field.mult(gamma, delta), field.mult(beta, gamma)) ^  field.mult(field.mult(gamma, alpha), field.mult(gamma, alpha)) ^field.mult(field.mult(gamma, gamma), field.mult(delta, beta)) ^

            field.mult(field.mult(delta, delta), field.mult(delta, delta)) ^ field.mult(field.mult(delta, alpha), field.mult(alpha, beta)) ^ field.mult(field.mult(delta, beta), field.mult(gamma, gamma))
    }

    // Use part of the hard coded 4x4 matrix inversion algorithm to get the inverted polynomial by inverting the circulant matrix generated by the polynomial
    fn invert_polynomial(field: & PrimitivePolynomialField, polynomial: & [u8; ROW_SIZE]) -> [u8; ROW_SIZE] {

        let mut result = [0; 4];

        let alpha = polynomial[0];
        let beta = polynomial[1];
        let gamma = polynomial[2];
        let delta = polynomial[3];

        let determinant = determinant(field, polynomial);

        result[0] = field.div(field.mult(field.mult(alpha, alpha), alpha) ^field.mult(field.mult(beta, beta), gamma) ^field.mult(field.mult(gamma, delta), delta) ^
                                  field.mult(field.mult(alpha, beta), delta) ^field.mult(field.mult(beta, delta), alpha) ^field.mult(field.mult(gamma, alpha), gamma), determinant);

        result[1] = field.div(field.mult(field.mult(beta, beta), delta) ^field.mult(field.mult(gamma, delta), alpha) ^field.mult(field.mult(delta, alpha), gamma) ^
                                  field.mult(field.mult(beta, alpha), alpha) ^field.mult(field.mult(gamma, beta), gamma) ^field.mult(field.mult(delta, delta), delta), determinant);

        result[2] = field.div(field.mult(field.mult(beta, beta), alpha) ^field.mult(field.mult(gamma, gamma), gamma) ^field.mult(field.mult(delta, alpha), delta) ^
                                  field.mult(field.mult(beta, gamma), delta) ^field.mult(field.mult(gamma, alpha), alpha) ^field.mult(field.mult(delta, beta), gamma), determinant);

        result[3] = field.div(field.mult(field.mult(beta, gamma), alpha) ^field.mult(field.mult(gamma, alpha), beta) ^field.mult(field.mult(delta, beta), delta) ^
                                  field.mult(field.mult(beta, beta), beta) ^field.mult(field.mult(gamma, gamma), delta) ^field.mult(field.mult(delta, alpha), alpha), determinant);

        result
    }

    pub struct AmES
    {
        _key: Key<Self>,

        //_schedule: [u8; STATE_SIZE],

        _generator: ChaChaRng,

        _sbox: RandomRijndaelSBox,

        _field: PrimitivePolynomialField,

        _polynomial: [u8; ROW_SIZE],
        _permutation: [u8; STATE_SIZE],
        _sequence: Vec<Action>,

        _inv_polynomial: [u8; ROW_SIZE],
        _inv_permutation: [u8; STATE_SIZE],
        _rev_sequence: Vec<Action>
    }

    impl NewBlockCipher for AmES {
        type KeySize = U32;

        fn new(key: & Key<Self>) -> Self {

            //This will become the field over which all cipher arithmatic is performed
            let field = PrimitivePolynomialField::new(IrreducablePolynomial::Poly84320).expect("Not a primitive");

            /* Copy the key */
            let master_key = key.clone();

            /* Setup the cryptographically secure reproducable random number generator */
            let mut generator = ChaChaRng::from_seed(<<ChaChaRng as SeedableRng>::Seed>::from(master_key));

            /* Get the number of 'rounds' used in the algorithm */
            let round_count = generator.gen_range(ROUND_COUNT_RANGE);

            /* Get the sequence of actions */
            //Produce an AES like algorithm, with one Action after another. Action1, Action 2, Action3, Action 1, Action 2, ...
            let mut sequence: Vec<_> = (0..round_count*ACTION_COUNT).into_iter().map(|x| Action::from_u32(x % ACTION_COUNT).unwrap()).collect();

            sequence.shuffle(& mut generator);

            /* Get the sbox */
            let mut sbox = RandomRijndaelSBox::new(& mut generator);

            while !sbox.is_valid() {
                sbox = RandomRijndaelSBox::new(& mut generator);
            }

            /* Get the polynmial, ensuring the determinant of the circulant matrix generated from the polkynomial is non-zero */
            let mut polynomial = [0; ROW_SIZE];

            let uniform_byte = Uniform::from(0..=255);

            //Keep generating random ppolynomials until we find one with a non-zero determinant
            while !is_valid_polynomial(&field, &polynomial) {
                for coeff in polynomial.iter_mut() {
                    *coeff = uniform_byte.sample(& mut generator);
                }
            }

            /* Get the permutation vector */
            let mut permutation = [0; STATE_SIZE];

            for (i, element) in permutation.iter_mut().enumerate() {
                *element = i as u8;
            }

            while !is_valid_permutation(&permutation) {
                permutation.shuffle(&mut generator);
            }

            /* Calculate the inverse of all the actions */
            let inverse_poly = invert_polynomial(&field, &polynomial);
            let inverse_perm = invert_map(& permutation);
            let reverse_sequ = sequence.iter().rev().map(|x| *x).collect();

            AmES {
                _key: master_key,

                _generator: generator,

                _sbox: sbox,

                _field: field,

                _polynomial: polynomial,
                _permutation: permutation,
                _sequence: sequence,

                _inv_polynomial: inverse_poly,
                _inv_permutation: inverse_perm,
                _rev_sequence: reverse_sequ
            }
        }

    }

    impl BlockCipher for AmES {
        type BlockSize = U16;
        type ParBlocks = U1;

        fn encrypt_block(&self, block: &mut Block<Self>) {
            let mut state = State::new(&self._field, block.as_mut_slice());

            state.transform(&self._sequence, self._key.as_slice(), &self._polynomial, &self._permutation, |x| self._sbox.forward(x));
        }

        fn decrypt_block(&self, block: &mut Block<Self>) {
            let mut state = State::new(&self._field, block.as_mut_slice());

            state.transform(&self._rev_sequence, self._key.as_slice(), &self._inv_polynomial, &self._inv_permutation, |x| self._sbox.reverse(x));
        }


    }
}