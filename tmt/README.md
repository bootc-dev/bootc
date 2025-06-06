# Run integration test locally

In the bootc CI, integration tests are executed via Packit on the Testing Farm. In addition, the integration tests can also be run locally on a developer's machine, which is especially valuable for debugging purposes.

To run integration tests locally, you need to [install tmt](https://tmt.readthedocs.io/en/stable/guide.html#the-first-steps) first. Then, use `tmt run -vvvvv plans -n integration` command to run the all integration tests.

To run integration tests on different distros, just change `image: fedora-rawhide` in https://github.com/bootc-dev/bootc/blob/9d15eedea0d54a4dbc15d267dbdb055817336254/tmt/plans/integration.fmf#L6.

The available images value can be found from https://tmt.readthedocs.io/en/stable/plugins/provision.html#images.

Enjoy integration test local running!
