use std::hash::{Hash, Hasher};
#[cfg(feature = "python")]
use std::sync::Arc;

use num_bigint::BigUint;

/// A wrapper excluded from identity: all `Ignored<T>` compare equal and hash to
/// nothing, so a field of this type is skipped by its container's derived
/// `Eq`/`Ord`/`Hash`. The wrapped value is still carried.
#[derive(Debug, Clone)]
pub struct Ignored<T>(pub T);

impl<T> PartialEq for Ignored<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl<T> Eq for Ignored<T> {}
impl<T> PartialOrd for Ignored<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Ignored<T> {
    fn cmp(&self, _: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}
impl<T> std::hash::Hash for Ignored<T> {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}
impl<T> From<T> for Ignored<T> {
    fn from(value: T) -> Self {
        Ignored(value)
    }
}

/// This struct is a sort of hack to allow us to access data in python
/// annotations, while supporting unknown annotations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnnotationType {
    /// A user-defined Python annotation, held as the Python object itself.
    #[cfg(feature = "python")]
    PyAnnotation {
        /// `module:class` of the Python object. The module keeps same-named
        /// classes from different modules apart.
        name: String,
        /// The Python object. `Ignored` excludes it from the annotation's
        /// identity; the `Arc` lets the annotation be cloned without the GIL.
        object: Ignored<Arc<pyo3::Py<pyo3::PyAny>>>,
        /// Hash of the Python object; identifies the annotation.
        obj_hash: i64,
    },
    SimplificationAvoidance,
    StridedInterval {
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    },
    EmptyStridedInterval,
    Region {
        region_id: String,
        region_base_addr: BigUint,
    },
    Uninitialized,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Annotation {
    type_: AnnotationType,
    eliminatable: bool,
    relocatable: bool,
}

impl Annotation {
    pub fn new(type_: AnnotationType, eliminatable: bool, relocatable: bool) -> Self {
        Annotation {
            type_,
            eliminatable,
            relocatable,
        }
    }

    /// The annotation's class name.
    pub fn name(&self) -> &str {
        match self.type_ {
            #[cfg(feature = "python")]
            AnnotationType::PyAnnotation { ref name, .. } => {
                name.rsplit_once(':').map_or(name, |(_, class)| class)
            }
            AnnotationType::SimplificationAvoidance => "SimplificationAvoidanceAnnotation",
            AnnotationType::StridedInterval { .. } => "StridedIntervalAnnotation",
            AnnotationType::EmptyStridedInterval => "EmptyStridedIntervalAnnotation",
            AnnotationType::Region { .. } => "RegionAnnotation",
            AnnotationType::Uninitialized => "UninitializedAnnotation",
        }
    }

    pub fn type_(&self) -> &AnnotationType {
        &self.type_
    }

    pub fn eliminatable(&self) -> bool {
        self.eliminatable
    }

    pub fn relocatable(&self) -> bool {
        self.relocatable
    }

    pub fn identity_hash(&self) -> u64 {
        let mut hasher = crate::context::deterministic_hasher();
        self.hash(&mut hasher);
        hasher.finish()
    }
}
