# Scanner readiness controls

These small source fixtures are build inputs for scanner readiness checks.
They include deliberately unsafe examples and corresponding controls. Treat
them as source only; do not deploy or execute the vulnerable applications.

The scanner image copies the OpenGrep, Bearer, dependency and infrastructure
fixtures into its canary directory. After data validation, preparation uses
the expected detections to check that the enabled engines can actually scan.
A successful image build alone does not establish scanner readiness.

The contributor baseline runs scanner unit tests from
`services/scanner/tests`. Private release controllers, historical diagnostic
admissions and their runtime inventories are not distributed here.
