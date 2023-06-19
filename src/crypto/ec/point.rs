/* Author: Stefan Goetz, 2023
Warranty Disclaimer: the software is provided "as is" without any warranties or conditions.
Implementation according to 
*/

use super::x25519::{FieldElement, unpack25519};

#[derive(Copy, Clone, Debug)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
}

impl Point {
    pub fn new(xx: [u8; 32], yy: [u8; 32]) -> Self {
        Self {
            x: unpack25519(&xx),
            y: unpack25519(&yy),
        }
    }
}