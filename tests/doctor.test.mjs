import test from "node:test";
import assert from "node:assert/strict";
import { versionAtLeast } from "../scripts/doctor.mjs";

test("doctor compares stable Node and Herdr versions numerically", () => {
	assert.equal(versionAtLeast("herdr 0.7.1", "0.7.5"), false);
	assert.equal(versionAtLeast("herdr 0.7.5", "0.7.5"), true);
	assert.equal(versionAtLeast("herdr 0.10.0", "0.7.5"), true);
	assert.equal(versionAtLeast("v20.9.0", "20.10"), false);
	assert.equal(versionAtLeast("v24.13.0", "20.10"), true);
	assert.equal(versionAtLeast("v20.10.0", "20.10"), true);
	assert.equal(versionAtLeast("0.7.5-rc.1", "0.7.5"), false);
	assert.equal(versionAtLeast("unavailable", "0.7.5"), false);
});
