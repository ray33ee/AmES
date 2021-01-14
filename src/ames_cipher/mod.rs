
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

    pub trait SBox {
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

    pub struct RandomRijndaelSBox {
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
            let mult = rng.gen_range(2..=255);
            let add = rng.gen_range(1..=255);

            RandomRijndaelSBox {
                _field: GeneralField::new(IrreducablePolynomial::Poly84310),
                _mult: mult,
                _add: add
            }
        }

    }

    pub struct RandomSbox {
        _forward: Vec<u8>,
        _reverse: Vec<u8>
    }

    impl SBox for RandomSbox {

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

            RandomSbox {
                _forward: forward,
                _reverse: reverse
            }
        }

    }

    pub struct AesSbox {
        _forward: Vec<u8>,
        _reverse: Vec<u8>
    }

    impl SBox for AesSbox {

        fn forward(&self, byte: u8) -> u8 {
            self._forward[byte as usize]
        }

        fn reverse(&self, byte: u8) -> u8 {
            self._reverse[byte as usize]
        }

        fn new<R: Rng + ?Sized>(rng: & mut R) -> Self {
            let mut forward: Vec<u8> = vec![0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];

            let mut reverse = vec![0; 256];

            for (i, map_element) in forward.iter().enumerate() {
                reverse[*map_element as usize] = i as u8;
            }

            AesSbox {
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

        fn scramble(& mut self, permutation: & [usize; STATE_SIZE]) {
            let mut tmp = [0; STATE_SIZE];

            for (tmp_byte, permuter) in tmp.iter_mut().zip(permutation.iter()) {
                *tmp_byte = self._array[*permuter]
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
                        permutation: & [usize; STATE_SIZE],
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

    /*
        A derangement is a permutation with no fixed points, producing one means we no longer need to check for fixed points
        when we create permutations. To randomly generate a derangement, we first note that any permutation can be written as
        a product of disjoint cycles. Ensuring that these cycles contain 2 or more elements, ensures that the permutation is
        a derangement. Here is a proposed algorithm to generate random derangements.

            1. First we start with a list of numbers
                [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            2. Then we use the shuffle function to randmly rearrange the list
                [3, 8, 7, 6, 5, 14, 11, 1, 4, 12, 10, 0, 9, 15, 2, 13]

                NOTE: The shuffle algorithm does not protect against fixed points, as shown above (10 maps to 10)

            3. Next we randomly partition the shuffled list into cycles, being sure not to create or leave any fixed points
                (3, 8, 7)(6, 5, 14, 11)(1, 4)(12, 10, 0)(9, 15, 2, 13)

            4. Finally we convert this back into a permutation
                [12, 4, 13, 8, 1, 14, 6, 3, 7, 15, 0, 6, 10, 9, 11, 2]

        When partitioning the set, it is important to ensure we do not create any fixed cycles. Lets
        say there are n values left to partition. This means that the next partition could be in the
        range 2..=n-2 or the entire partition, n itself. To achieve this in the algorithm, we get random
        numbers in the range 2..=n-1, and if it returns n-1, we map this to n.

    */
    fn generate_derangement<R: Rng + ?Sized>(rng: & mut R) -> [usize; STATE_SIZE] {
        let mut permutation= [0; STATE_SIZE];
        let mut derangement = [0; STATE_SIZE];

        // Fill the permutation with 0..STATE_SIZE
        for (i, element) in permutation.iter_mut().enumerate() {
            *element = i;
        }

        //Shuffle the permutation
        permutation.shuffle( rng);

        //Get a slice representing the remaining elements to partition
        let mut remaining = &permutation[..];

        // Randomly partition and convert from cyclic to permutation notation
        while remaining.len() != 0 {

            //If there are only 2 elements left, the partition size MUST be 2. Otherwise randomly get the pertition size
            let mut partition_size = if remaining.len() == 2
                {
                    2
                }
                else {
                    rng.gen_range(2..=remaining.len()-1)
                };

            if partition_size == remaining.len()-1 { //Special case
                partition_size = remaining.len();
            }

            //Get a slice representing the partition
            let partition = &remaining[..partition_size];

            //Iterate over the partiton, treating it as a cycle and converting it into standard form
            for (i, element) in partition.iter().enumerate() {
                derangement[*element] = partition[(i+1) % partition_size];
            }

            //Move the slice forward
            remaining = &remaining[partition_size..];
        }

        derangement
    }

    fn invert_map(map: & [usize]) -> [usize; STATE_SIZE] {
        let mut inverted = [0; STATE_SIZE];

        for (i, map_element) in map.iter().enumerate() {
            inverted[*map_element] = i;
        }

        inverted
    }

    //Using the explicit formula for the determinant of a 4x4 matrix, we obtain a quartic equation with respect to
    //'delta'. The following function returns the coefficiants of x^0, x^1 and x^2 of this equation. (The coefficients
    //of x^3 and x^4 are omitted since they are 0 and 1, respectively.
    fn get_coeffs(field: & PrimitivePolynomialField, polynomial: & [u8; ROW_SIZE]) -> (u8, u8, u8) {
        let alpha = polynomial[0];
        let beta = polynomial[1];
        let gamma = polynomial[2];

        let coeff0 = field.mult(field.mult(alpha, alpha), field.mult(alpha, alpha)) ^
            field.mult(field.mult(alpha, beta), field.mult(beta, gamma)) ^
            field.mult(field.mult(beta, beta), field.mult(gamma, alpha)) ^
            field.mult(field.mult(beta, gamma), field.mult(alpha, beta)) ^
            field.mult(field.mult(gamma, alpha), field.mult(beta, beta)) ^
            field.mult(field.mult(gamma, gamma), field.mult(gamma, gamma)) ^
            field.mult(field.mult(alpha, gamma), field.mult(alpha, gamma)) ^
            field.mult(field.mult(gamma, alpha), field.mult(gamma, alpha)) ^
            field.mult(field.mult(beta, beta), field.mult(beta, beta));

        let coeff1 = field.mult(alpha, field.mult(beta, alpha)) ^
            field.mult(beta, field.mult(alpha, alpha)) ^
            field.mult(beta, field.mult(alpha, alpha)) ^
            field.mult(gamma, field.mult(gamma, beta)) ^
            field.mult(gamma, field.mult(beta, gamma)) ^
            field.mult(gamma, field.mult(gamma, beta)) ^
            field.mult(alpha, field.mult(alpha, beta)) ^
            field.mult(beta, field.mult(gamma, gamma));


        let coeff2 = field.mult(alpha, gamma) ^
            field.mult(beta, beta) ^
            field.mult(gamma, alpha) ^
            field.mult(alpha, gamma) ^
            field.mult(gamma, alpha) ^
            field.mult(beta, beta);

        (coeff0, coeff1, coeff2)
    }

    //The following function calculates the determinant by evalusting the quartic equation (as defined
    //in the get_coeffs function) using the calculated coefficients and the value for delta
    fn determinant_quartic(coeffs: (u8, u8, u8), x: u8, field: & PrimitivePolynomialField) -> u8 {
        field.mult(field.mult(field.mult(x, x) ^ coeffs.2, x) ^ coeffs.1, x) ^ coeffs.0
    }

    // Returns the determinant of the 4x4 circulant matrix generated by 'polynomial'
    /*fn determinant(field: & PrimitivePolynomialField, polynomial: & [u8; ROW_SIZE]) -> u8 {
/*
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
*/

        determinant_quartic(get_coeffs(field, polynomial), polynomial[3], field)
    }*/



    /*
        Not all randomly generated polynomials with coefficients in GF(2^8) are valid, since some
        may result in a circulant matrix with a determinant = 0, and are therefore not invertable.
        Here we propose a more efficient method than randomly generating polynomials until we have a non-zero
        determinant. Generally (though there are exceptions, such as if some of the coefficients are zero)
        the first three coefficients may be chosen randomly without fear of producing a non-invertable
        polynomial. However, when selecting the final coefficient, it is possible to generate a
        non-invertable polynomial. Substituting the first three coefficients into the explicit formula
        for the determinant of a 4x4 matrix gives us a quartic equation with respect to the 4th
        coefficient of the polynomial. We then randomly select values for the 4th coefficient until
        we find one that produces a non-zero determinant. While still requiring random guesses, this
        method only requires us to guess a new byte (instead of an arreay of 4) and it only evaluates
        a polynomial each time, instead of needing to calculate the determinant each time.
    */
    fn generate_polynomial<R: Rng + ?Sized>(rng: & mut R, field: & PrimitivePolynomialField) -> (u8, [u8; ROW_SIZE]) {
        let mut polynomial = [0u8; ROW_SIZE];

        let uniform_byte = Uniform::from(1..=255);

        polynomial[0] = uniform_byte.sample(rng);
        polynomial[1] = uniform_byte.sample(rng);
        polynomial[2] = uniform_byte.sample(rng);

        let quartic_coeffs = get_coeffs(field, &polynomial);

        let mut determinant = 0;

        while determinant == 0 {
            polynomial[3] = uniform_byte.sample(rng);

            determinant = determinant_quartic(quartic_coeffs, polynomial[3], field);
        }

        (determinant, polynomial)
    }

    // Use part of the hard coded 4x4 matrix inversion algorithm to get the inverted polynomial by inverting the circulant matrix generated by the polynomial
    fn invert_polynomial(field: & PrimitivePolynomialField, polynomial: & [u8; ROW_SIZE], determinant: u8) -> [u8; ROW_SIZE] {

        let mut result = [0; 4];

        let alpha = polynomial[0];
        let beta = polynomial[1];
        let gamma = polynomial[2];
        let delta = polynomial[3];

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

    pub struct AmES<S: SBox>
    {
        _key: Key<Self>,

        //_schedule: [u8; STATE_SIZE],

        _generator: ChaChaRng,

        _sbox: S,

        _field: PrimitivePolynomialField,

        _polynomial: [u8; ROW_SIZE],
        _permutation: [usize; STATE_SIZE],
        _sequence: Vec<Action>,

        _inv_polynomial: [u8; ROW_SIZE],
        _inv_permutation: [usize; STATE_SIZE],
        _rev_sequence: Vec<Action>
    }

    impl<S: SBox> NewBlockCipher for AmES<S> {
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
            let mut sbox = S::new(& mut generator);

            while !sbox.is_valid() {
                sbox = S::new(& mut generator);
            }

            /* Get the polynmial, ensuring the determinant of the circulant matrix generated from the polkynomial is non-zero */
            /*let mut polynomial = [0; ROW_SIZE];

            let uniform_byte = Uniform::from(0..=255);

            //Keep generating random ppolynomials until we find one with a non-zero determinant
            while !is_valid_polynomial(&field, &polynomial) {
                for coeff in polynomial.iter_mut() {
                    *coeff = uniform_byte.sample(& mut generator);
                }
            }*/
            let (determinant, polynomial) = generate_polynomial(& mut generator, &field);

            /* Get the permutation vector */
            let permutation = generate_derangement(& mut generator);

            /* Calculate the inverse of all the actions */
            let inverse_poly = invert_polynomial(&field, &polynomial, determinant);
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

    impl<S: SBox> BlockCipher for AmES<S> {
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

    pub type AmESArraySbox = AmES<RandomSbox>;
    pub type AmESRijndaelSbox = AmES<RandomRijndaelSBox>;
    pub type AmESStaticSbox = AmES<AesSbox>;
}