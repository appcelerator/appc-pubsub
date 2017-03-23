module.exports = function (grunt) {

	grunt.initConfig({
		eslint: {
			target: [ '*.js', 'lib/**/*.js', 'test/**/*.js' ]
		},

		mocha_istanbul: {
			coverage: {
				src: 'test',
				options: {
					timeout: 30000,
					reporter: 'spec',
					ignoreLeaks: false
				}
			}
		},

		clean: [ 'tmp' ]
	});

	// Load grunt plugins for modules
	grunt.loadNpmTasks('grunt-eslint');
	grunt.loadNpmTasks('grunt-mocha-istanbul');
	grunt.loadNpmTasks('grunt-contrib-clean');

	// register tasks
	grunt.registerTask('default', [ 'eslint', 'mocha_istanbul:coverage', 'clean' ]);
};
