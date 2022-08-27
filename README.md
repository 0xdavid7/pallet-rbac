#RBAC

## This repository is cloned from [substrate-rbac](https://github.com/gautamdhameja/substrate-rbac)
## I have just adjusted the version of dependencies
1. polkadot: v9.26
2. nightly: v1.65
3. others: in `Cargo.toml`, v6.0.0 instead of v4.0.0-dev

-->
##Substrate Role-based Access Control Pallet

A [Substrate](https://github.com/paritytech/substrate) pallet implementing role-based access control and permissions for Substrate extrinsic calls.

The filtering of incoming extrinsics and their sender accounts is done at the transaction queue validation layer, using the `SignedExtension` trait.

## Usage

* Add the module's dependency in the `Cargo.toml` of your `runtime` directory. Make sure to enter the correct path or git url of the pallet as per your setup.

```toml
[dependencies.substrate_rbac]
package = 'substrate-rbac'
git = 'https://github.com/gautamdhameja/substrate-rbac.git'
default-features = false
```

* Declare the pallet in your `runtime/src/lib.rs`.

```rust
pub use substrate_rbac;

impl substrate_rbac::Config for Runtime {
    type Event = Event;
    type RbacAdminOrigin = EnsureRoot<AccountId>;
}

construct_runtime!(
    pub enum Runtime where
        Block = Block,
        NodeBlock = opaque::Block,
        UncheckedExtrinsic = UncheckedExtrinsic
    {
        ...
        ...
        ...
        RBAC: substrate_rbac::{Pallet, Call, Storage, Event<T>, Config<T>},
    }
);
```

* Add the module's `Authorize` type in the `SignedExtra` checklist.

```rust
pub type SignedExtra = (
    ...
    ...
    balances::TakeFees<Runtime>,
    substrate_rbac::Authorize<Runtime>
```

* Add a genesis configuration for the module in the `src/chain_spec.rs` file.

```rust
rbac: Some(RBACConfig {
	super_admins: vec![get_account_id_from_seed::<sr25519::Public>("Alice")]
})
```

* `cargo build --release` and then `cargo run --release -- --dev`

## Sample

The usage of this pallet are demonstrated in the [Substrate permissioning sample](https://github.com/gautamdhameja/substrate-permissioning).

## Disclaimer

This code not audited and reviewed for production use cases. You can expect bugs and security vulnerabilities. Do not use it as-is in real applications.
