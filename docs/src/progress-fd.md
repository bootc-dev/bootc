
# Interactive progress with `--progress-fd`

While the `bootc status` tooling allows a client to discover the state
of the system, during interactive changes such as `bootc upgrade`
or `bootc switch` it is possible to monitor the status of downloads
or other operations at a fine-grained level with `--progress-fd`.

The format of data output over `--progress-fd` is [JSON Lines](https://jsonlines.org)
which is a series of JSON objects separated by newlines (the intermediate
JSON content is guaranteed not to contain a literal newline).

You can find the JSON schema describing this version here:
[progress-v0.schema.json](progress-v0.schema.json).

Deploying a new image with either switch or upgrade consists
of three stages: `pulling`, `importing`, and `staging`. The `pulling` step
downloads the image from the registry, offering per-layer and progress in
each message. The `importing` step imports the image into storage and consists
of a single step. Finally, `staging` runs a variety of staging
tasks. Currently, they are staging the image to disk, pulling bound images,
and removing old images.

Note that new stages or fields may be added at any time.

Importing and staging are affected by disk speed and the total image size. Pulling
is affected by network speed and how many layers invalidate between pulls.
Therefore, a large image with a good caching strategy will have longer
importing and staging times, and a small bespoke container image will have
negligible importing and staging times.
