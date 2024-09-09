extern crate prost_build;

fn main() {
    prost_build::compile_protos(
        &["protos/pack.proto", "protos/timestamp.proto"],
        &["protos/"],
    )
    .unwrap();
}
