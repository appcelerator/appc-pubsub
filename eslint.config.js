const axwayNode = require('eslint-config-axway/env-node');
const axwayMocha = require('eslint-config-axway/+mocha');
const { defineConfig } = require('eslint/config');

module.exports = defineConfig({
	files: [
		'./**/*.{js,mjs}'
	],
	ignores: [
		'./coverage/**',
		'./node_modules*/**'
	],
	extends: [ axwayNode, axwayMocha ],
	languageOptions: {
		ecmaVersion: 'latest'
	}
});
