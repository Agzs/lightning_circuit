###  Run rustc test (ubuntu 16.04)

1. Make sure you have installed the dependencies:

   * `g++` 4.7 or `clang++` 3.x
   * `python` 2.6 or later (but not 3.x)
   * GNU `make` 3.81 or later
   * `curl`
   * `git`

2. Clone the [source] with `git`:

   ```sh
   $ git clone https://github.com/rust-lang/rust.git
   $ cd rust
   ```
[source]: https://github.com/rust-lang/rust.git

3. Switch and check branch:

   ```sh
   $ git checkout 1.3.0
   $ git branch
   ```

   There will show 

3. Build and install rustc:

    ```sh
    $ ./configure
    $ make
    $ sudo make install
    ```

    When complete, `make install` will place several programs into
    `/usr/local/bin`: `rustc`, the Rust compiler, and `rustdoc`, the
    API-documentation tool. This install does not include [Cargo],
    Rust's package manager, which you may also want to build.

[Cargo]: https://github.com/rust-lang/cargo

    > ***Note:*** You may need to run again if you meet some error about 
    > git or curl. Choosing ubuntu 32bits may be better if you still meet
    > some else errors after that. 
    

4. Install cargo:

    ```sh
    $ sudo apt-get install cargo
    ```

5. Run test:

    ```sh
    $ cd lightning_circuit/gen_tests
    $ cargo build
    $ cargo run
    ```
### rust doc
    [Rust (Chinese-version)](https://kaisery.github.io/trpl-zh-cn/)

    [Rust library](https://doc.rust-lang.org/0.11.0/rustc/util/sha2/struct.Sha256.html?search=as_ref)

    [Rust playground](https://play.rust-lang.org/?version=stable&mode=debug)