const test = require("node:test");
const assert = require("node:assert/strict");
const { add } = require("./app");

test("adds two positive numbers", () => {
  assert.equal(add(2, 3), 5);
});

test("adds negative numbers", () => {
  assert.equal(add(-2, -3), -5);
});

test("adds zero", () => {
  assert.equal(add(5, 0), 5);
});
