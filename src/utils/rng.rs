/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
*/

use rand::Rng;

pub fn fill_array(to_fill: &mut [u8; 32]) {
    let mut rng: rand::rngs::ThreadRng = rand::thread_rng();

    for i in 0..32 {
        to_fill[i] = rng.gen();
    }
}