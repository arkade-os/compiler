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
    let err = compile(src).expect_err("expected a shadowing error").to_string();
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
    assert!(
        compile(src).is_ok(),
        "expected clean compile: {:?}",
        compile(src).err()
    );
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
contract Demo(pubkey[] ks) {
  function f(signature[] sigs, bytes32 msg) {
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
    assert!(
        compile(src).is_ok(),
        "expected clean compile: {:?}",
        compile(src).err()
    );
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
    let err = compile(src).expect_err("expected a shadowing error").to_string();
    assert!(
        err.contains("shadows an in-scope binding"),
        "unexpected error: {err}"
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
    let err = compile(src).expect_err("expected a shadowing error").to_string();
    assert!(
        err.contains("shadows an in-scope binding"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_inner_loop_var_shadowing_outer_loop_var() {
    let src = r#"
contract Demo(pubkey[] ks) {
  function f(signature[] sigs, bytes32 msg) {
    for (i, s) in sigs {
      for (i, t) in sigs {
        require(checkSigFromStack(s, ks[i], msg));
      }
    }
  }
}
"#;
    let err = compile(src).expect_err("expected a shadowing error").to_string();
    assert!(
        err.contains("shadows an in-scope binding"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_loop_var_shadowing_constructor_param() {
    let src = r#"
contract Demo(int i) {
  function f(signature[] sigs, pubkey[] ks, bytes32 msg) {
    for (i, s) in sigs {
      require(checkSigFromStack(s, ks[i], msg));
    }
  }
}
"#;
    let err = compile(src).expect_err("expected a shadowing error").to_string();
    assert!(
        err.contains("shadows an in-scope binding"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_identical_loop_variables() {
    let src = r#"
contract Demo(pubkey[] ks) {
  function f(signature[] sigs, bytes32 msg) {
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
fn accepts_sibling_scope_reuse() {
    // let x in both branches; the same loop vars in two separate loops.
    let src = r#"
contract Demo(pubkey[] ks) {
  function f(signature[] sigs, bytes32 msg, int flag) {
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
    assert!(
        compile(src).is_ok(),
        "expected clean compile: {:?}",
        compile(src).err()
    );
}
