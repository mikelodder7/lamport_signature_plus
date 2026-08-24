/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use std::hash::Hash;

use std::ops::{
    Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
};
use zeroize::Zeroize;

/// A multidimensional vector that is faster and simpler than `Vec<Vec<T>>`.
#[derive(Debug)]
pub struct MultiVec<T, const D: usize> {
    pub(crate) data: Vec<T>,
    pub(crate) axes: [usize; D],
}

impl<T, const D: usize> Default for MultiVec<T, D> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            axes: [0; D],
        }
    }
}

impl<T: Copy, const D: usize> MultiVec<T, D> {
    /// Constructs a [`MultiVec`] with the specified axes and fills it with the specified value.
    pub fn fill(axes: [usize; D], value: T) -> Self {
        let data = vec![value; axes.iter().product()];
        Self { data, axes }
    }
}

impl<T: PartialEq, const D: usize> PartialEq for MultiVec<T, D> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.axes == other.axes
    }
}

impl<T: Eq, const D: usize> Eq for MultiVec<T, D> {}

impl<T: PartialOrd, const D: usize> PartialOrd for MultiVec<T, D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.data.partial_cmp(&other.data)
    }
}

impl<T: Ord, const D: usize> Ord for MultiVec<T, D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.data.cmp(&other.data)
    }
}

impl<T: Clone, const D: usize> Clone for MultiVec<T, D> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            axes: self.axes,
        }
    }
}

impl<T: Hash, const D: usize> Hash for MultiVec<T, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.axes.hash(state);
    }
}

impl<T, const D: usize> AsRef<[T]> for MultiVec<T, D> {
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T, const D: usize> AsMut<[T]> for MultiVec<T, D> {
    fn as_mut(&mut self) -> &mut [T] {
        &mut self.data
    }
}

impl<T: Zeroize, const D: usize> Zeroize for MultiVec<T, D> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<T, const D: usize> MultiVec<T, D> {
    /// Constructs a [`MultiVec`] with the specified axes.
    pub fn new(axes: [usize; D]) -> Self {
        assert!(axes.iter().all(|&x| x > 0));
        Self {
            data: Vec::with_capacity(axes.iter().product()),
            axes,
        }
    }

    /// Constructs a [`MultiVec`] with the specified axes and fills it with the result of the function.
    pub fn fill_fn(axes: [usize; D], f: impl Fn(usize) -> T) -> Self {
        let data = (0..axes.iter().product()).map(f).collect();
        Self { data, axes }
    }

    /// Performs an isomorphism on the axes. The new axes must have the same number of elements.
    pub fn iso(&mut self, new_axes: [usize; D]) {
        assert_eq!(
            self.axes.iter().product::<usize>(),
            new_axes.iter().product::<usize>()
        );
        self.axes = new_axes;
    }

    /// Returns an iterator over references to the elements.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter()
    }

    /// Returns an iterator over mutable references to the elements.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.data.iter_mut()
    }

    /// Returns the number of elements.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the [`MultiVec`] is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<T> MultiVec<T, 2> {
    fn begin(&self, index: usize) -> usize {
        index * self.axes[1]
    }

    /// Converts the [`MultiVec`] to a [`Vec`].
    pub fn to_vec(self) -> Vec<T> {
        self.data
    }
}

impl<T> Index<usize> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, i: usize) -> &[T] {
        &self[(i, ..)]
    }
}

impl<T> Index<(usize, usize)> for MultiVec<T, 2> {
    type Output = T;

    fn index(&self, (i, j): (usize, usize)) -> &T {
        &self.data[self.begin(i) + j]
    }
}

impl<T> Index<(usize, Range<usize>)> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, (i, j): (usize, Range<usize>)) -> &[T] {
        let b = self.begin(i);
        &self.data[b + j.start..b + j.end]
    }
}

impl<T> Index<(usize, RangeFull)> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, (i, _): (usize, RangeFull)) -> &[T] {
        let b = self.begin(i);
        let e = b + self.axes[1];
        &self.data[b..e]
    }
}

impl<T> Index<(usize, RangeFrom<usize>)> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, (i, j): (usize, RangeFrom<usize>)) -> &[T] {
        let b = self.begin(i);
        let e = b + self.axes[1];
        &self.data[b + j.start..e]
    }
}

impl<T> Index<(usize, RangeTo<usize>)> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, (i, j): (usize, RangeTo<usize>)) -> &[T] {
        let b = self.begin(i);
        &self.data[b..b + j.end]
    }
}

impl<T> Index<(usize, RangeInclusive<usize>)> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, (i, j): (usize, RangeInclusive<usize>)) -> &[T] {
        let b = self.begin(i);
        &self.data[b + j.start()..b + j.end() + 1]
    }
}

impl<T> Index<(usize, RangeToInclusive<usize>)> for MultiVec<T, 2> {
    type Output = [T];

    fn index(&self, (i, j): (usize, RangeToInclusive<usize>)) -> &[T] {
        let b = self.begin(i);
        &self.data[b..b + j.end + 1]
    }
}

impl<T> IndexMut<usize> for MultiVec<T, 2> {
    fn index_mut(&mut self, i: usize) -> &mut [T] {
        &mut self[(i, ..)]
    }
}

impl<T> IndexMut<(usize, usize)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut T {
        let b = self.begin(i);
        &mut self.data[b + j]
    }
}

impl<T> IndexMut<(usize, Range<usize>)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, j): (usize, Range<usize>)) -> &mut [T] {
        let b = self.begin(i);
        &mut self.data[b + j.start..b + j.end]
    }
}

impl<T> IndexMut<(usize, RangeFull)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, _): (usize, RangeFull)) -> &mut [T] {
        let b = self.begin(i);
        let e = b + self.axes[1];
        &mut self.data[b..e]
    }
}

impl<T> IndexMut<(usize, RangeFrom<usize>)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, j): (usize, RangeFrom<usize>)) -> &mut [T] {
        let b = self.begin(i);
        let e = b + self.axes[1];
        &mut self.data[b + j.start..e]
    }
}

impl<T> IndexMut<(usize, RangeTo<usize>)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, j): (usize, RangeTo<usize>)) -> &mut [T] {
        let b = self.begin(i);
        &mut self.data[b..b + j.end]
    }
}

impl<T> IndexMut<(usize, RangeInclusive<usize>)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, j): (usize, RangeInclusive<usize>)) -> &mut [T] {
        let b = self.begin(i);
        &mut self.data[b + j.start()..b + j.end() + 1]
    }
}

impl<T> IndexMut<(usize, RangeToInclusive<usize>)> for MultiVec<T, 2> {
    fn index_mut(&mut self, (i, j): (usize, RangeToInclusive<usize>)) -> &mut [T] {
        let b = self.begin(i);
        &mut self.data[b..b + j.end + 1]
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn construction_and_traits() {
        let empty = MultiVec::<u8, 2>::default();
        assert!(empty.is_empty());

        let reserved = MultiVec::<u8, 2>::new([2, 3]);
        assert!(reserved.is_empty());

        let mut values =
            MultiVec::fill_fn([2, 3], |i| u8::try_from(i).expect("test indices fit in u8"));
        assert_eq!(values.len(), 6);
        assert_eq!(values.as_ref(), &[0, 1, 2, 3, 4, 5]);
        values.as_mut()[0] = 9;
        values.iter_mut().for_each(|value| *value += 1);
        assert_eq!(
            values.iter().copied().collect::<Vec<_>>(),
            [10, 2, 3, 4, 5, 6]
        );

        let cloned = values.clone();
        assert_eq!(values, cloned);
        assert_eq!(values.partial_cmp(&cloned), Some(std::cmp::Ordering::Equal));
        assert_eq!(values.cmp(&cloned), std::cmp::Ordering::Equal);

        let mut left_hasher = DefaultHasher::new();
        values.hash(&mut left_hasher);
        let mut right_hasher = DefaultHasher::new();
        cloned.hash(&mut right_hasher);
        assert_eq!(left_hasher.finish(), right_hasher.finish());

        values.iso([3, 2]);
        assert_eq!(values.to_vec(), vec![10, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn immutable_index_variants() {
        let values = MultiVec::fill_fn([2, 4], |i| i);
        assert_eq!(values[1], [4, 5, 6, 7]);
        assert_eq!(values[(1, 2)], 6);
        assert_eq!(values[(1, 1..3)], [5, 6]);
        assert_eq!(values[(1, ..)], [4, 5, 6, 7]);
        assert_eq!(values[(1, 2..)], [6, 7]);
        assert_eq!(values[(1, ..2)], [4, 5]);
        assert_eq!(values[(1, 1..=2)], [5, 6]);
        assert_eq!(values[(1, ..=2)], [4, 5, 6]);
    }

    #[test]
    fn mutable_index_variants() {
        let mut values = MultiVec::fill([2, 8], 0u8);
        values[0].copy_from_slice(&[1; 8]);
        values[(0, 0)] = 2;
        values[(0, 1..3)].copy_from_slice(&[3, 4]);
        values[(0, 3..)].copy_from_slice(&[5, 6, 7, 8, 9]);
        values[(1, ..2)].copy_from_slice(&[10, 11]);
        values[(1, 2..=3)].copy_from_slice(&[12, 13]);
        values[(1, ..=7)].copy_from_slice(&[14; 8]);
        values[(1, ..)].copy_from_slice(&[15; 8]);

        assert_eq!(values[0], [2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(values[1], [15; 8]);
    }

    #[test]
    fn zeroize_clears_values() {
        let mut values = MultiVec::fill([2, 2], 7u8);
        values.zeroize();
        assert!(values.is_empty());
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn new_rejects_zero_axis() {
        let _ = MultiVec::<u8, 2>::new([0, 2]);
    }

    #[test]
    #[should_panic(expected = "assertion")]
    fn iso_rejects_different_element_count() {
        let mut values = MultiVec::fill([2, 2], 0u8);
        values.iso([1, 3]);
    }
}
