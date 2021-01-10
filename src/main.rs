use galois_2p8::{IrreducablePolynomial, PrimitivePolynomialField};
use std::fmt;
use galois_2p8::Field;

use std::time::{Instant};

const STATE_SIZE: usize = 16;
const ROW_SIZE: usize = 4;

#[derive(Debug, Clone, Copy)]
enum Action {
    XOR,
    Scramble,
    Linear,
    SBox
}

struct ArraySbox {
    _forward: Vec<u8>,
    _reverse: Vec<u8>
}

impl ArraySbox {
    fn new(list: Vec<u8>) -> Self {
        let mut reverse = vec![0; 256];

        for (i, map_element) in list.iter().enumerate() {
            reverse[*map_element as usize] = i as u8;
        }

        ArraySbox {
            _forward: list,
            _reverse: reverse
        }
    }

    fn forward(&self, byte: u8) -> u8 {
        self._forward[byte as usize]
    }

    fn reverse(&self, byte: u8) -> u8 {
        self._reverse[byte as usize]
    }

}

struct State<'a> {
    _field: & 'a PrimitivePolynomialField,
    _array: [u8; STATE_SIZE]
}

impl fmt::Debug for State<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("_array", &self._array)
            .field("_field", &IrreducablePolynomial::Poly84310)
            .finish()
    }
}

impl<'a> State<'a> {
    fn new(field: & 'a PrimitivePolynomialField, array: [u8; STATE_SIZE]) -> Self {
        State {
            _field: field,
            _array: array
        }
    }

    fn xor(& mut self, key: & [u8; STATE_SIZE]) {
        for (state_byte, key_byte) in self._array.iter_mut().zip(key.iter()) {
            *state_byte = self._field.add(*key_byte, *state_byte);
        }
    }

    fn scramble(& mut self, permutation: & [u8; STATE_SIZE]) {
        let mut tmp = [0; STATE_SIZE];

        for (tmp_byte, permuter) in tmp.iter_mut().zip(permutation.iter()) {
            *tmp_byte = self._array[*permuter as usize]
        }

        self._array = tmp;
    }

    fn linear(& mut self, polynomial: & [u8; ROW_SIZE]) {
        for i in 0..ROW_SIZE {
            let row = & mut self._array[i*ROW_SIZE..i*ROW_SIZE+ROW_SIZE];

            let mut new_row = [0u8; ROW_SIZE];

            for (j, new_row_element) in new_row.iter_mut().enumerate() {

                for (k, row_element) in row.iter().enumerate() {
                    //Perform some dirty modular arithmetic to shift each row
                    let polynomial_element = polynomial[(k + 7 - j) % ROW_SIZE];
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
                 key: & [u8; STATE_SIZE],
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

fn invert_map(map: & [u8]) -> [u8; STATE_SIZE] {
    let mut inverted = [0; STATE_SIZE];

    for (i, map_element) in map.iter().enumerate() {
        inverted[*map_element as usize] = i as u8;
    }

    inverted
}

fn main() {

    let field = PrimitivePolynomialField::new(IrreducablePolynomial::Poly84320).expect("Not a primitive");

    let data = [45, 38, 49, 76, 0, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150];

    let key = [49, 34, 174, 243, 241, 148, 38, 43, 227, 59, 178, 170, 238, 125, 93, 157];

    let mut state = State::new(&field, data);

    let sbox = ArraySbox::new(
        vec![29, 45, 216, 58, 164, 57, 39, 12, 64, 21, 244, 3, 34, 232, 44, 190, 140, 137, 89, 32, 26, 170, 103, 62, 210, 9, 147, 214, 117, 194, 143, 197, 204, 22, 174, 220, 100, 255, 17, 200, 71, 14, 225, 139, 180, 234, 226, 0, 10, 125, 222, 122, 142, 78, 209, 199, 110, 238, 195, 132, 213, 115, 4, 85, 183, 182, 5, 86, 158, 254, 11, 151, 175, 191, 233, 179, 223, 97, 215, 119, 90, 186, 13, 235, 76, 161, 127, 250, 207, 178, 7, 219, 80, 145, 98, 55, 162, 196, 6, 144, 63, 167, 243, 113, 69, 172, 65, 75, 53, 101, 153, 94, 131, 46, 201, 92, 230, 79, 1, 245, 56, 43, 121, 169, 218, 123, 228, 72, 24, 41, 163, 141, 114, 173, 242, 165, 150, 18, 159, 42, 120, 60, 240, 99, 251, 52, 88, 146, 253, 192, 38, 23, 189, 82, 31, 33, 133, 16, 138, 176, 96, 187, 231, 155, 198, 205, 111, 149, 118, 47, 124, 177, 102, 83, 91, 30, 211, 148, 95, 221, 112, 48, 128, 130, 168, 236, 105, 193, 129, 136, 212, 249, 51, 67, 229, 104, 156, 25, 247, 37, 70, 126, 74, 108, 184, 109, 135, 154, 239, 116, 54, 66, 49, 203, 40, 20, 202, 35, 166, 208, 160, 36, 68, 217, 107, 87, 15, 77, 246, 61, 248, 157, 81, 252, 241, 171, 134, 188, 28, 227, 152, 185, 237, 93, 106, 8, 206, 2, 73, 224, 27, 50, 59, 84, 181, 19]
    );

    let permutation = [3, 4, 11, 9, 7, 0, 5, 15, 10, 6, 2, 13, 8, 12, 14, 1];
    let invert_perm = invert_map(&permutation);

    let polynomial = [3, 1, 1, 2];
    let inverse_poly = [11, 13, 9, 14];

    let action_sequence = [Action::Linear, Action::Scramble, Action::SBox, Action::XOR, Action::Scramble, Action::SBox, Action::Scramble, Action::XOR, Action::SBox, Action::Linear];
    let reverse_sequence: Vec<_> = action_sequence.iter().rev().map(|x| *x).collect();


    println!("State: {:?}", state);

    let start = Instant::now();
    state.transform(&action_sequence, &key, &polynomial, &permutation, |x| sbox.forward(x));
    let duration = start.elapsed();

    println!("State: {:?}", state);

    state.transform(reverse_sequence.as_slice(), &key, &inverse_poly, &invert_perm, |x| sbox.reverse(x));

    println!("State: {:?}", state);


    println!("Transform duration: {:?}", duration);


    //println!("Compare: {}", state == data);
}
