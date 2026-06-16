use std::str::FromStr;

use indexmap::IndexSet;
use serde::Serialize;

pub type SubjectId = u64;
pub type OwnerSet = IndexSet<SubjectId>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessKind {
    Read,
    Write,
    ReadWrite,
    Free,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViolationKind {
    UninitializedRead,
    OutOfBoundsRead,
    OutOfBoundsWrite,
    UseAfterFreeRead,
    UseAfterFreeWrite,
    StackUseAfterScopeRead,
    StackUseAfterScopeWrite,
    DoubleFree,
    InvalidFree,
    MemoryOverlap,
    CrossBoundary,
    DanglingPointer,
    ExpiredPointerDereference,
    NullPointerDereference,
    UntrustedPtr,
}

impl ViolationKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::UninitializedRead,
            Self::OutOfBoundsRead,
            Self::OutOfBoundsWrite,
            Self::UseAfterFreeRead,
            Self::UseAfterFreeWrite,
            Self::StackUseAfterScopeRead,
            Self::StackUseAfterScopeWrite,
            Self::DoubleFree,
            Self::InvalidFree,
            Self::MemoryOverlap,
            Self::CrossBoundary,
            Self::DanglingPointer,
            Self::ExpiredPointerDereference,
            Self::NullPointerDereference,
            Self::UntrustedPtr,
        ]
    }
}

impl FromStr for ViolationKind {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace(['_', '-'], "");
        match normalized.as_str() {
            "uninitializedread" => Ok(Self::UninitializedRead),
            "outofboundsread" | "oobr" => Ok(Self::OutOfBoundsRead),
            "outofboundswrite" | "outofboundeswrite" | "oobw" => Ok(Self::OutOfBoundsWrite),
            "uafread" | "useafterfreeread" => Ok(Self::UseAfterFreeRead),
            "uafwrite" | "useafterfreewrite" => Ok(Self::UseAfterFreeWrite),
            "stackuseafterscoperead" | "stackreadafterscope" | "stackuafread" => {
                Ok(Self::StackUseAfterScopeRead)
            }
            "stackuseafterscopewrite" | "stackwriteafterscope" | "stackuafwrite" => {
                Ok(Self::StackUseAfterScopeWrite)
            }
            "doublefree" => Ok(Self::DoubleFree),
            "invalidfree" => Ok(Self::InvalidFree),
            "memoryoverlap" | "memoverlap" | "overlap" => Ok(Self::MemoryOverlap),
            "crossboundary" | "crossboundarypointer" => Ok(Self::CrossBoundary),
            "danglingpointer" | "danglingptr" | "dangling" => Ok(Self::DanglingPointer),
            "expiredpointerdereference" | "expiredptr" | "expiredderef" => {
                Ok(Self::ExpiredPointerDereference)
            }
            "nullpointerdereference" | "nullpointerderef" | "nullpointer" => {
                Ok(Self::NullPointerDereference)
            }
            "untrustedptr" | "untrustedpointer" => Ok(Self::UntrustedPtr),
            other => Err(format!("unknown vulnerability type '{other}'")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub step: u64,
    pub pc: String,
    pub kind: ViolationKind,
    pub access: AccessKind,
    pub address: String,
    pub size: String,
    pub pointer_owners: Vec<String>,
    pub cell_owners: Vec<String>,
    pub value_owners: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
