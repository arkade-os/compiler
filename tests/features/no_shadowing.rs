use arkade_compiler::compile;

#[test]
fn rejects_function_param_shadowing_constructor_param() {
    let src = r#"
contract Demo(int amount) {
  function f(int amount) {
    require(amount >= 1);
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a shadowing error")
        .to_string();
    assert!(
        err.contains("shadows constructor parameter"),
        "unexpected error: {err}"
    );
}

#[test]
fn accepts_distinct_names() {
    let src = r#"
contract Demo(int limit) {
  function f(signature sig, pubkey pk) {
    require(checkSig(sig, pk));
    require(limit >= 1);
  }
}
"#;
    let result = compile(src);
    assert!(result.is_ok(), "expected clean compile: {:?}", result.err());
}

#[test]
fn rejects_assignment_to_constructor_param() {
    let src = r#"
contract Demo(int amount) {
  function f(signature sig, pubkey pk) {
    amount = 5;
    require(checkSig(sig, pk));
  }
}
"#;
    let err = compile(src)
        .expect_err("expected an immutability error")
        .to_string();
    assert!(
        err.contains("cannot assign to constructor parameter"),
        "unexpected error: {err}"
    );
}

#[test]
fn allows_reassignment_of_local() {
    // `int valid = 0;` then `valid = valid + 1;` — the documented pattern.
    let src = r#"
contract Demo(pubkey[3] ks) {
  function f(signature[3] sigs, bytes32 msg) {
    int valid = 0;
    for (i, s) in sigs {
      if (checkSigFromStack(s, ks[i], msg)) {
        valid = valid + 1;
      }
    }
    require(valid >= 1);
  }
}
"#;
    let result = compile(src);
    assert!(result.is_ok(), "expected clean compile: {:?}", result.err());
}

#[test]
fn rejects_local_shadowing_function_param() {
    let src = r#"
contract Demo(int limit) {
  function f(int amount) {
    int amount = 5;
    require(amount >= 1);
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a shadowing error")
        .to_string();
    assert_eq!(
        err.matches("shadows an in-scope binding").count(),
        1,
        "{err}"
    );
}

#[test]
fn rejects_nested_local_shadowing_enclosing_local() {
    let src = r#"
contract Demo(int limit) {
  function f(signature sig, pubkey pk) {
    int x = 1;
    if (limit >= 1) {
      int x = 2;
      require(x >= 1);
    }
    require(checkSig(sig, pk));
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a shadowing error")
        .to_string();
    assert!(
        err.contains("shadows an in-scope binding"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_inner_loop_var_shadowing_outer_loop_var() {
    let src = r#"
contract Demo(pubkey[3] ks) {
  function f(signature[3] sigs, bytes32 msg) {
    for (i, s) in sigs {
      for (i, t) in sigs {
        require(checkSigFromStack(s, ks[i], msg));
      }
    }
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a shadowing error")
        .to_string();
    assert_eq!(
        err.matches("shadows an in-scope binding").count(),
        1,
        "{err}"
    );
}

#[test]
fn rejects_loop_var_shadowing_constructor_param() {
    let src = r#"
contract Demo(int i) {
  function f(signature[3] sigs, pubkey[3] ks, bytes32 msg) {
    for (i, s) in sigs {
      require(checkSigFromStack(s, ks[i], msg));
    }
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a shadowing error")
        .to_string();
    assert!(
        err.contains("shadows an in-scope binding"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_identical_loop_variables() {
    let src = r#"
contract Demo(pubkey[3] ks) {
  function f(signature[3] sigs, bytes32 msg) {
    for (x, x) in sigs {
      require(checkSigFromStack(x, ks[0], msg));
    }
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a duplicate loop-variable error")
        .to_string();
    assert!(err.contains("must differ"), "unexpected error: {err}");
}

#[test]
fn rejects_array_element_colliding_with_scalar_param() {
    // Constructor `int[3] xs` -> xs_0, xs_1, xs_2 ; function `int xs_0` -> xs_0.
    let src = r#"
contract Demo(int[3] xs) {
  function f(int xs_0) {
    require(xs_0 >= 1);
  }
}
"#;
    let err = compile(src)
        .expect_err("expected a namespace collision error")
        .to_string();
    assert!(
        err.contains("collide in the emitted namespace"),
        "unexpected error: {err}"
    );
}

#[test]
fn flattened_abi_names_do_not_alias_array_elements() {
    let cases = [
        r#"
contract Demo(int[3] xs) {
  function f() {
    require(xs_0 >= 1);
  }
}
"#,
        r#"
contract Demo() {
  function f(int[3] xs) {
    xs_0 = 5;
    require(xs[0] >= 1);
  }
}
"#,
        r#"
contract Demo(pubkey[3] keys) {
  function f(signature sig, bytes32 msg) {
    require(checkSigFromStack(sig, keys_0, msg));
  }
}
"#,
    ];

    for source in cases {
        let error = compile(source)
            .expect_err("flattened ABI name must not resolve as an array element")
            .to_string();
        assert!(
            error.contains("undefined") || error.contains("undeclared"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn source_bindings_can_reuse_flattened_abi_names() {
    let source = r#"
contract Demo(int[3] xs) {
  function f() {
    let xs_0 = 1;
    require(xs[0] >= xs_0);
  }
}
"#;

    let output = compile(source).expect("source and internal array bindings must remain distinct");
    let covenant = crate::common::group(&output, "f")
        .arkade
        .as_ref()
        .expect("covenant");
    assert!(covenant.asm.iter().all(|token| !token.contains("$array:")));
}

#[test]
fn rejects_tapscript_array_expansion_collisions() {
    // Tapscript inputs cannot be arrays, so the collision can only come from a
    // constructor array expanding onto a declared tapscript input name.
    let error = compile(
        r#"
contract Demo(pubkey[3] owners) {
  function leaf(signature sig, pubkey owners_0) tapscript {
    require(checkSig(sig, owners_0));
  }
}
"#,
    )
    .expect_err("expanded tapscript names must not collide")
    .to_string();
    assert!(
        error.contains("collide in the emitted namespace"),
        "unexpected error: {error}"
    );
}

#[test]
fn accepts_sibling_scope_reuse() {
    // let x in both branches; the same loop vars in two separate loops.
    let src = r#"
contract Demo(pubkey[3] ks) {
  function f(signature[3] sigs, bytes32 msg, int flag) {
    if (flag >= 1) {
      int x = 1;
      require(x >= 1);
    } else {
      int x = 2;
      require(x >= 1);
    }
    for (i, s) in sigs {
      require(checkSigFromStack(s, ks[i], msg));
    }
    for (i, s) in sigs {
      require(checkSigFromStack(s, ks[i], msg));
    }
  }
}
"#;
    let result = compile(src);
    assert!(result.is_ok(), "expected clean compile: {:?}", result.err());
}
