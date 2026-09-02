# Mount External Storage

Mount object storage (Amazon S3, Cloudflare R2, Tigris, Supabase Storage, Google Cloud Storage, Azure Blob), cloud storage like Box, and filesystems like Archil and MesaFS into a Daytona sandbox as a regular directory. The sandbox reads from and writes to the bucket as if it were a local directory, so existing tools, scripts, and agents work without changes. This is useful for bringing in datasets, model weights, or build artifacts that already live in your own cloud account.

External storage mounts and [Daytona Volumes](https://www.daytona.io/docs/en/volumes.md) are complementary FUSE-based mechanisms — both expose remote object storage as a regular sandbox directory, both can be shared across sandboxes, and both persist beyond any individual sandbox's lifetime. The main distinction is **where the data physically lives**: Daytona Volumes are hosted on Daytona's own S3-compatible object store, while external mounts connect to a bucket or filesystem hosted on another provider (Amazon S3, Cloudflare R2, Tigris, Supabase Storage, GCS, Azure Blob, Box, Archil, MesaFS).

External storage is mounted using FUSE. Daytona supports two approaches, and each provider section below shows both — pick whichever fits your workflow:

- **Pre-built snapshot** — build a [snapshot](https://www.daytona.io/docs/en/snapshots.md) once with the FUSE tool (`mount-s3`, `gcsfuse`, `blobfuse2`, `rclone`) built-in, then launch every sandbox from that snapshot. Cold starts are fast and predictable. Best for production.
- **Runtime install** — launch a default sandbox and `apt-get install` the FUSE tool when the sandbox starts. Adds time to sandbox startup, but you don't manage snapshots. Best for quick experiments.

Both approaches end with the same mount command and the same usage — the only difference is when the FUSE tool gets installed.

## Mount an Amazon S3 bucket

Mount an S3 bucket using [Mountpoint for Amazon S3 ↗](https://github.com/awslabs/mountpoint-s3) — AWS's official FUSE client, optimized for high throughput on S3.

**Credentials** — set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in your local environment. The snippets below pass them into the sandbox via `envVars`, and `mount-s3` reads them from there.

### Pre-built snapshot

Build a snapshot with `mount-s3` preinstalled, then launch all S3-enabled sandboxes from that snapshot. This removes per-sandbox package install work, keeps cold starts predictable, and gives you a reusable baseline image for production workloads.

#### Build a snapshot

Create a reusable snapshot that installs `mount-s3` and its system dependencies. After it finishes, every sandbox launched from `fuse-s3` already has the mount binary available.


```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb "
    "&& rm /tmp/mount-s3.deb",
  )
)

daytona.snapshot.create(
    CreateSnapshotParams(name="fuse-s3", image=image),
    on_logs=print,
)
```


```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' +
    '&& rm /tmp/mount-s3.deb',
)

await daytona.snapshot.create(
  { name: 'fuse-s3', image },
  { onLogs: console.log },
)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

image = Daytona::Image
  .base('daytonaio/sandbox')
  .run_commands(
    'sudo apt-get update ' \
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
    '&& wget -O /tmp/mount-s3.deb ' \
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' \
    '&& rm /tmp/mount-s3.deb'
  )

daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(name: 'fuse-s3', image: image),
  on_logs: proc { |chunk| print(chunk) }
)
```


```go
import (
    "context"
    "fmt"
    "log"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

image := daytona.Base("daytonaio/sandbox").
    Run("sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget").
    Run(`arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && ` +
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && ` +
        `sudo apt-get install -y /tmp/mount-s3.deb && rm /tmp/mount-s3.deb`)

_, logChan, err := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
    Name:  "fuse-s3",
    Image: image,
})
if err != nil {
    log.Fatal(err)
}
for line := range logChan {
    fmt.Print(line)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Image;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Image image = Image.base("daytonaio/sandbox")
                .runCommands(
                    "sudo apt-get update "
                        + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
                    "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                        + "&& wget -O /tmp/mount-s3.deb "
                        + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                        + "&& sudo apt-get install -y /tmp/mount-s3.deb "
                        + "&& rm /tmp/mount-s3.deb"
                );

            daytona.snapshot().create("fuse-s3", image, System.out::println);
        }
    }
}
```


#### Launch and mount

Pass AWS credentials as environment variables on sandbox creation. `mount-s3` reads them automatically.


```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-s3",
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["AWS_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["AWS_SECRET_ACCESS_KEY"],
        },
    )
)

mount_path = "/home/daytona/s3"

# mount-s3 daemonizes by default and reads AWS_* from the environment
sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(f"mount-s3 my-bucket {mount_path}")

# Read and write through the mount as if it were a local directory
sandbox.process.exec(f"echo 'hello from Daytona' > {mount_path}/hello.txt")
response = sandbox.process.exec(f"cat {mount_path}/hello.txt")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const sandbox = await daytona.create({
  snapshot: 'fuse-s3',
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY!,
  },
})

const mountPath = '/home/daytona/s3'

// mount-s3 daemonizes by default and reads AWS_* from the environment
await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(`mount-s3 my-bucket ${mountPath}`)

// Read and write through the mount as if it were a local directory
await sandbox.process.executeCommand(`echo 'hello from Daytona' > ${mountPath}/hello.txt`)
const response = await sandbox.process.executeCommand(`cat ${mountPath}/hello.txt`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

sandbox = daytona.create(
  Daytona::CreateSandboxFromSnapshotParams.new(
    snapshot: 'fuse-s3',
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('AWS_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('AWS_SECRET_ACCESS_KEY')
    }
  )
)

mount_path = '/home/daytona/s3'

# mount-s3 daemonizes by default and reads AWS_* from the environment
sandbox.process.exec(command: "mkdir -p #{mount_path}")
sandbox.process.exec(command: "mount-s3 my-bucket #{mount_path}")

# Read and write through the mount as if it were a local directory
sandbox.process.exec(command: "echo 'hello from Daytona' > #{mount_path}/hello.txt")
response = sandbox.process.exec(command: "cat #{mount_path}/hello.txt")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

sandbox, err := client.Create(ctx, types.SnapshotParams{
    Snapshot: "fuse-s3",
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("AWS_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

mountPath := "/home/daytona/s3"

// mount-s3 daemonizes by default and reads AWS_* from the environment
if _, err := sandbox.Process.ExecuteCommand(ctx, "mkdir -p "+mountPath); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx, "mount-s3 my-bucket "+mountPath); err != nil {
    log.Fatal(err)
}

// Read and write through the mount as if it were a local directory
if _, err := sandbox.Process.ExecuteCommand(ctx, "echo 'hello from Daytona' > "+mountPath+"/hello.txt"); err != nil {
    log.Fatal(err)
}
response, err := sandbox.Process.ExecuteCommand(ctx, "cat "+mountPath+"/hello.txt")
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setSnapshot("fuse-s3");
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("AWS_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("AWS_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            String mountPath = "/home/daytona/s3";

            // mount-s3 daemonizes by default and reads AWS_* from the environment
            sandbox.getProcess().executeCommand("mkdir -p " + mountPath);
            sandbox.getProcess().executeCommand("mount-s3 my-bucket " + mountPath);

            // Read and write through the mount as if it were a local directory
            sandbox.getProcess().executeCommand(
                "echo 'hello from Daytona' > " + mountPath + "/hello.txt");
            ExecuteResponse response = sandbox.getProcess().executeCommand(
                "cat " + mountPath + "/hello.txt");
            System.out.println(response.getResult());
        }
    }
}
```


### Runtime install

Start from a default sandbox and install `mount-s3` during startup before running the mount command. This is useful for quick testing and temporary environments where you do not want to maintain a custom snapshot, with the tradeoff of slower cold starts.


```python
import os
from daytona import CreateSandboxBaseParams, Daytona

daytona = Daytona()

sandbox = daytona.create(
    CreateSandboxBaseParams(
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["AWS_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["AWS_SECRET_ACCESS_KEY"],
        },
    )
)

# Install mount-s3 at runtime
sandbox.process.exec(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"
)
sandbox.process.exec(
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb"
)

# Mount and use
mount_path = "/home/daytona/s3"
sandbox.process.exec(f"mkdir -p {mount_path} && mount-s3 my-bucket {mount_path}")
response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const sandbox = await daytona.create({
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY!,
  },
})

// Install mount-s3 at runtime
await sandbox.process.executeCommand(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
)
await sandbox.process.executeCommand(
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb',
)

// Mount and use
const mountPath = '/home/daytona/s3'
await sandbox.process.executeCommand(`mkdir -p ${mountPath} && mount-s3 my-bucket ${mountPath}`)
const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

sandbox = daytona.create(
  Daytona::CreateSandboxBaseParams.new(
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('AWS_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('AWS_SECRET_ACCESS_KEY')
    }
  )
)

# Install mount-s3 at runtime
sandbox.process.exec(
  command: 'sudo apt-get update ' \
           '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget'
)
sandbox.process.exec(
  command: 'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
           '&& wget -O /tmp/mount-s3.deb ' \
           '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
           '&& sudo apt-get install -y /tmp/mount-s3.deb'
)

# Mount and use
mount_path = '/home/daytona/s3'
sandbox.process.exec(command: "mkdir -p #{mount_path} && mount-s3 my-bucket #{mount_path}")
response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

sandbox, err := client.Create(ctx, types.SnapshotParams{
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("AWS_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("AWS_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

// Install mount-s3 at runtime
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    `arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && `+
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && `+
        `sudo apt-get install -y /tmp/mount-s3.deb`); err != nil {
    log.Fatal(err)
}

// Mount and use
mountPath := "/home/daytona/s3"
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mkdir -p "+mountPath+" && mount-s3 my-bucket "+mountPath); err != nil {
    log.Fatal(err)
}
response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("AWS_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("AWS_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            // Install mount-s3 at runtime
            sandbox.getProcess().executeCommand(
                "sudo apt-get update "
                    + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget");
            sandbox.getProcess().executeCommand(
                "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                    + "&& wget -O /tmp/mount-s3.deb "
                    + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                    + "&& sudo apt-get install -y /tmp/mount-s3.deb");

            // Mount and use
            String mountPath = "/home/daytona/s3";
            sandbox.getProcess().executeCommand(
                "mkdir -p " + mountPath + " && mount-s3 my-bucket " + mountPath);
            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```


## Mount a Cloudflare R2 bucket

Cloudflare R2 is S3-compatible, so the same `mount-s3` tool works. Pass an explicit `--endpoint-url` pointing at your R2 account.

**Credentials** — set `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, and `R2_SECRET_ACCESS_KEY` in your local environment. R2 is S3-compatible, so the snippets below pass your R2 keys into the sandbox via `envVars` under the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` names that `mount-s3` expects.

### Pre-built snapshot

Build a snapshot with `mount-s3` preinstalled, then launch all R2-enabled sandboxes from that snapshot. The mount flow stays identical to S3 except for the R2 `--endpoint-url`, and startup remains fast because installation is done once at snapshot build time.

#### Build a snapshot

Create a reusable snapshot that installs the same `mount-s3` tool used for S3. R2 remains S3-compatible, so this snapshot is identical to S3 setup and only the runtime mount command changes.


```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb "
    "&& rm /tmp/mount-s3.deb",
  )
)

daytona.snapshot.create(
    CreateSnapshotParams(name="fuse-r2", image=image),
    on_logs=print,
)
```


```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' +
    '&& rm /tmp/mount-s3.deb',
)

await daytona.snapshot.create(
  { name: 'fuse-r2', image },
  { onLogs: console.log },
)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

image = Daytona::Image
  .base('daytonaio/sandbox')
  .run_commands(
    'sudo apt-get update ' \
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
    '&& wget -O /tmp/mount-s3.deb ' \
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' \
    '&& rm /tmp/mount-s3.deb'
  )

daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(name: 'fuse-r2', image: image),
  on_logs: proc { |chunk| print(chunk) }
)
```


```go
import (
    "context"
    "fmt"
    "log"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

image := daytona.Base("daytonaio/sandbox").
    Run("sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget").
    Run(`arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && ` +
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && ` +
        `sudo apt-get install -y /tmp/mount-s3.deb && rm /tmp/mount-s3.deb`)

_, logChan, err := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
    Name:  "fuse-r2",
    Image: image,
})
if err != nil {
    log.Fatal(err)
}
for line := range logChan {
    fmt.Print(line)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Image;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Image image = Image.base("daytonaio/sandbox")
                .runCommands(
                    "sudo apt-get update "
                        + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
                    "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                        + "&& wget -O /tmp/mount-s3.deb "
                        + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                        + "&& sudo apt-get install -y /tmp/mount-s3.deb "
                        + "&& rm /tmp/mount-s3.deb"
                );

            daytona.snapshot().create("fuse-r2", image, System.out::println);
        }
    }
}
```


#### Launch and mount

Pass your R2 credentials into the sandbox as `AWS_*` environment variables and mount with the R2 endpoint URL. This keeps the authentication flow compatible with `mount-s3` while targeting your Cloudflare account.


```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

# R2 credentials live in your Cloudflare dashboard under R2 > Manage API Tokens
account_id = os.environ["R2_ACCOUNT_ID"]

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-r2",
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["R2_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["R2_SECRET_ACCESS_KEY"],
        },
    )
)

mount_path = "/home/daytona/r2"

sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(
    f"mount-s3 --endpoint-url https://{account_id}.r2.cloudflarestorage.com "
    f"my-r2-bucket {mount_path}"
)

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

// R2 credentials live in your Cloudflare dashboard under R2 > Manage API Tokens
const accountId = process.env.R2_ACCOUNT_ID!

const sandbox = await daytona.create({
  snapshot: 'fuse-r2',
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.R2_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.R2_SECRET_ACCESS_KEY!,
  },
})

const mountPath = '/home/daytona/r2'

await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(
  `mount-s3 --endpoint-url https://${accountId}.r2.cloudflarestorage.com ` +
    `my-r2-bucket ${mountPath}`,
)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

# R2 credentials live in your Cloudflare dashboard under R2 > Manage API Tokens
account_id = ENV.fetch('R2_ACCOUNT_ID')

sandbox = daytona.create(
  Daytona::CreateSandboxFromSnapshotParams.new(
    snapshot: 'fuse-r2',
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('R2_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('R2_SECRET_ACCESS_KEY')
    }
  )
)

mount_path = '/home/daytona/r2'

sandbox.process.exec(command: "mkdir -p #{mount_path}")
sandbox.process.exec(
  command: "mount-s3 --endpoint-url https://#{account_id}.r2.cloudflarestorage.com " \
           "my-r2-bucket #{mount_path}"
)

response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

// R2 credentials live in your Cloudflare dashboard under R2 > Manage API Tokens
accountID := os.Getenv("R2_ACCOUNT_ID")

sandbox, err := client.Create(ctx, types.SnapshotParams{
    Snapshot: "fuse-r2",
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("R2_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("R2_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

mountPath := "/home/daytona/r2"

if _, err := sandbox.Process.ExecuteCommand(ctx, "mkdir -p "+mountPath); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mount-s3 --endpoint-url https://"+accountID+".r2.cloudflarestorage.com "+
        "my-r2-bucket "+mountPath); err != nil {
    log.Fatal(err)
}

response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            // R2 credentials live in your Cloudflare dashboard under R2 > Manage API Tokens
            String accountId = System.getenv("R2_ACCOUNT_ID");

            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setSnapshot("fuse-r2");
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("R2_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("R2_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            String mountPath = "/home/daytona/r2";

            sandbox.getProcess().executeCommand("mkdir -p " + mountPath);
            sandbox.getProcess().executeCommand(
                "mount-s3 --endpoint-url https://" + accountId + ".r2.cloudflarestorage.com "
                    + "my-r2-bucket " + mountPath);

            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```


### Runtime install

Start from a default sandbox and install `mount-s3` during startup, then mount your bucket with the R2 `--endpoint-url`. This path is convenient for prototyping or one-off tasks, but each new sandbox pays the package installation cost.


```python
import os
from daytona import CreateSandboxBaseParams, Daytona

daytona = Daytona()

account_id = os.environ["R2_ACCOUNT_ID"]

sandbox = daytona.create(
    CreateSandboxBaseParams(
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["R2_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["R2_SECRET_ACCESS_KEY"],
        },
    )
)

# Install mount-s3
sandbox.process.exec(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"
)
sandbox.process.exec(
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb"
)

# Mount with R2 endpoint
mount_path = "/home/daytona/r2"
sandbox.process.exec(
    f"mkdir -p {mount_path} && "
    f"mount-s3 --endpoint-url https://{account_id}.r2.cloudflarestorage.com "
    f"my-r2-bucket {mount_path}"
)
response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const accountId = process.env.R2_ACCOUNT_ID!

const sandbox = await daytona.create({
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.R2_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.R2_SECRET_ACCESS_KEY!,
  },
})

// Install mount-s3
await sandbox.process.executeCommand(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
)
await sandbox.process.executeCommand(
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb',
)

// Mount with R2 endpoint
const mountPath = '/home/daytona/r2'
await sandbox.process.executeCommand(
  `mkdir -p ${mountPath} && ` +
    `mount-s3 --endpoint-url https://${accountId}.r2.cloudflarestorage.com ` +
    `my-r2-bucket ${mountPath}`,
)
const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

account_id = ENV.fetch('R2_ACCOUNT_ID')

sandbox = daytona.create(
  Daytona::CreateSandboxBaseParams.new(
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('R2_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('R2_SECRET_ACCESS_KEY')
    }
  )
)

# Install mount-s3
sandbox.process.exec(
  command: 'sudo apt-get update ' \
           '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget'
)
sandbox.process.exec(
  command: 'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
           '&& wget -O /tmp/mount-s3.deb ' \
           '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
           '&& sudo apt-get install -y /tmp/mount-s3.deb'
)

# Mount with R2 endpoint
mount_path = '/home/daytona/r2'
sandbox.process.exec(
  command: "mkdir -p #{mount_path} && " \
           "mount-s3 --endpoint-url https://#{account_id}.r2.cloudflarestorage.com " \
           "my-r2-bucket #{mount_path}"
)
response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

accountID := os.Getenv("R2_ACCOUNT_ID")

sandbox, err := client.Create(ctx, types.SnapshotParams{
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("R2_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("R2_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

// Install mount-s3
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    `arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && `+
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && `+
        `sudo apt-get install -y /tmp/mount-s3.deb`); err != nil {
    log.Fatal(err)
}

// Mount with R2 endpoint
mountPath := "/home/daytona/r2"
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mkdir -p "+mountPath+" && "+
        "mount-s3 --endpoint-url https://"+accountID+".r2.cloudflarestorage.com "+
        "my-r2-bucket "+mountPath); err != nil {
    log.Fatal(err)
}
response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            String accountId = System.getenv("R2_ACCOUNT_ID");

            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("R2_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("R2_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            // Install mount-s3
            sandbox.getProcess().executeCommand(
                "sudo apt-get update "
                    + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget");
            sandbox.getProcess().executeCommand(
                "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                    + "&& wget -O /tmp/mount-s3.deb "
                    + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                    + "&& sudo apt-get install -y /tmp/mount-s3.deb");

            // Mount with R2 endpoint
            String mountPath = "/home/daytona/r2";
            sandbox.getProcess().executeCommand(
                "mkdir -p " + mountPath + " && "
                    + "mount-s3 --endpoint-url https://" + accountId + ".r2.cloudflarestorage.com "
                    + "my-r2-bucket " + mountPath);

            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```


## Mount a Tigris bucket

Mount a Tigris bucket with the same `mount-s3` tool used for S3. Pass `--endpoint-url https://t3.storage.dev`, because Tigris uses one global endpoint with no per-account subdomain. Tigris also supports bucket snapshots and copy-on-write forks through request headers, so each sandbox can use an isolated writable bucket without duplicating source data.

**Credentials** — set `TIGRIS_STORAGE_ACCESS_KEY_ID` and `TIGRIS_STORAGE_SECRET_ACCESS_KEY` in your local environment. The snippets below pass these into the sandbox via `envVars` under the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` names that `mount-s3` expects.

### Pre-built snapshot

Build a snapshot with `mount-s3` preinstalled, then launch Tigris sandboxes from that snapshot. The mount flow matches S3 except for the Tigris `--endpoint-url`, and startup stays fast because installation happens once during snapshot build.

#### Build a snapshot

Create a reusable snapshot that installs `mount-s3`. Because Tigris is S3-compatible, this setup matches S3 and only the runtime mount command changes.


```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb "
    "&& rm /tmp/mount-s3.deb",
  )
)

daytona.snapshot.create(
    CreateSnapshotParams(name="fuse-tigris", image=image),
    on_logs=print,
)
```


```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' +
    '&& rm /tmp/mount-s3.deb',
)

await daytona.snapshot.create(
  { name: 'fuse-tigris', image },
  { onLogs: console.log },
)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

image = Daytona::Image
  .base('daytonaio/sandbox')
  .run_commands(
    'sudo apt-get update ' \
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
    '&& wget -O /tmp/mount-s3.deb ' \
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' \
    '&& rm /tmp/mount-s3.deb'
  )

daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(name: 'fuse-tigris', image: image),
  on_logs: proc { |chunk| print(chunk) }
)
```


```go
import (
    "context"
    "fmt"
    "log"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

image := daytona.Base("daytonaio/sandbox").
    Run("sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget").
    Run(`arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && ` +
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && ` +
        `sudo apt-get install -y /tmp/mount-s3.deb && rm /tmp/mount-s3.deb`)

_, logChan, err := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
    Name:  "fuse-tigris",
    Image: image,
})
if err != nil {
    log.Fatal(err)
}
for line := range logChan {
    fmt.Print(line)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Image;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Image image = Image.base("daytonaio/sandbox")
                .runCommands(
                    "sudo apt-get update "
                        + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
                    "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                        + "&& wget -O /tmp/mount-s3.deb "
                        + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                        + "&& sudo apt-get install -y /tmp/mount-s3.deb "
                        + "&& rm /tmp/mount-s3.deb"
                );

            daytona.snapshot().create("fuse-tigris", image, System.out::println);
        }
    }
}
```


#### Launch and mount

Pass Tigris credentials into the sandbox as `AWS_*` environment variables, then mount with the Tigris endpoint URL. This keeps authentication compatible with `mount-s3` while targeting your Tigris account.


```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-tigris",
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["TIGRIS_STORAGE_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["TIGRIS_STORAGE_SECRET_ACCESS_KEY"],
        },
    )
)

mount_path = "/home/daytona/tigris"

sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(
    f"mount-s3 --endpoint-url https://t3.storage.dev "
    f"my-tigris-bucket {mount_path}"
)

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const sandbox = await daytona.create({
  snapshot: 'fuse-tigris',
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.TIGRIS_STORAGE_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.TIGRIS_STORAGE_SECRET_ACCESS_KEY!,
  },
})

const mountPath = '/home/daytona/tigris'

await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(
  `mount-s3 --endpoint-url https://t3.storage.dev ` +
    `my-tigris-bucket ${mountPath}`,
)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

sandbox = daytona.create(
  Daytona::CreateSandboxFromSnapshotParams.new(
    snapshot: 'fuse-tigris',
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('TIGRIS_STORAGE_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('TIGRIS_STORAGE_SECRET_ACCESS_KEY')
    }
  )
)

mount_path = '/home/daytona/tigris'

sandbox.process.exec(command: "mkdir -p #{mount_path}")
sandbox.process.exec(
  command: 'mount-s3 --endpoint-url https://t3.storage.dev ' \
           "my-tigris-bucket #{mount_path}"
)

response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

sandbox, err := client.Create(ctx, types.SnapshotParams{
    Snapshot: "fuse-tigris",
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("TIGRIS_STORAGE_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("TIGRIS_STORAGE_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

mountPath := "/home/daytona/tigris"

if _, err := sandbox.Process.ExecuteCommand(ctx, "mkdir -p "+mountPath); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mount-s3 --endpoint-url https://t3.storage.dev "+
        "my-tigris-bucket "+mountPath); err != nil {
    log.Fatal(err)
}

response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setSnapshot("fuse-tigris");
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("TIGRIS_STORAGE_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("TIGRIS_STORAGE_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            String mountPath = "/home/daytona/tigris";

            sandbox.getProcess().executeCommand("mkdir -p " + mountPath);
            sandbox.getProcess().executeCommand(
                "mount-s3 --endpoint-url https://t3.storage.dev "
                    + "my-tigris-bucket " + mountPath);

            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```


### Runtime install

Start from a default sandbox, install `mount-s3` during startup, then mount with the Tigris `--endpoint-url`. This path is convenient for prototyping or one-off tasks, but each new sandbox repeats package installation.


```python
import os
from daytona import CreateSandboxBaseParams, Daytona

daytona = Daytona()

sandbox = daytona.create(
    CreateSandboxBaseParams(
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["TIGRIS_STORAGE_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["TIGRIS_STORAGE_SECRET_ACCESS_KEY"],
        },
    )
)

# Install mount-s3
sandbox.process.exec(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"
)
sandbox.process.exec(
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb"
)

# Mount with Tigris endpoint
mount_path = "/home/daytona/tigris"
sandbox.process.exec(
    f"mkdir -p {mount_path} && "
    f"mount-s3 --endpoint-url https://t3.storage.dev "
    f"my-tigris-bucket {mount_path}"
)
response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const sandbox = await daytona.create({
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.TIGRIS_STORAGE_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.TIGRIS_STORAGE_SECRET_ACCESS_KEY!,
  },
})

// Install mount-s3
await sandbox.process.executeCommand(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
)
await sandbox.process.executeCommand(
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb',
)

// Mount with Tigris endpoint
const mountPath = '/home/daytona/tigris'
await sandbox.process.executeCommand(
  `mkdir -p ${mountPath} && ` +
    `mount-s3 --endpoint-url https://t3.storage.dev ` +
    `my-tigris-bucket ${mountPath}`,
)
const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

sandbox = daytona.create(
  Daytona::CreateSandboxBaseParams.new(
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('TIGRIS_STORAGE_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('TIGRIS_STORAGE_SECRET_ACCESS_KEY')
    }
  )
)

# Install mount-s3
sandbox.process.exec(
  command: 'sudo apt-get update ' \
           '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget'
)
sandbox.process.exec(
  command: 'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
           '&& wget -O /tmp/mount-s3.deb ' \
           '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
           '&& sudo apt-get install -y /tmp/mount-s3.deb'
)

# Mount with Tigris endpoint
mount_path = '/home/daytona/tigris'
sandbox.process.exec(
  command: "mkdir -p #{mount_path} && " \
           'mount-s3 --endpoint-url https://t3.storage.dev ' \
           "my-tigris-bucket #{mount_path}"
)
response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

sandbox, err := client.Create(ctx, types.SnapshotParams{
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("TIGRIS_STORAGE_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("TIGRIS_STORAGE_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

// Install mount-s3
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    `arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && `+
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && `+
        `sudo apt-get install -y /tmp/mount-s3.deb`); err != nil {
    log.Fatal(err)
}

// Mount with Tigris endpoint
mountPath := "/home/daytona/tigris"
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mkdir -p "+mountPath+" && "+
        "mount-s3 --endpoint-url https://t3.storage.dev "+
        "my-tigris-bucket "+mountPath); err != nil {
    log.Fatal(err)
}
response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("TIGRIS_STORAGE_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("TIGRIS_STORAGE_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            // Install mount-s3
            sandbox.getProcess().executeCommand(
                "sudo apt-get update "
                    + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget");
            sandbox.getProcess().executeCommand(
                "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                    + "&& wget -O /tmp/mount-s3.deb "
                    + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                    + "&& sudo apt-get install -y /tmp/mount-s3.deb");

            // Mount with Tigris endpoint
            String mountPath = "/home/daytona/tigris";
            sandbox.getProcess().executeCommand(
                "mkdir -p " + mountPath + " && "
                    + "mount-s3 --endpoint-url https://t3.storage.dev "
                    + "my-tigris-bucket " + mountPath);

            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```


### Mount a copy-on-write fork per sandbox

A Tigris bucket fork is a new bucket created from a snapshot of a source bucket. The fork shares underlying storage with the source until written to — new writes go only to the fork, and the source bucket and other forks are unaffected. Fork creation is constant-time regardless of source bucket size.

This pattern fits Daytona sandboxes when each sandbox needs a writable copy of a shared dataset (model weights, fixtures, golden data) without duplicating it on every launch.

**Prerequisite** — the source bucket must be created with snapshots enabled. This is a one-time setup, done outside the per-sandbox flow:

```typescript
import { createBucket } from '@tigrisdata/storage'

await createBucket('my-source-bucket', { enableSnapshot: true })
```

In any S3 SDK, send a `CreateBucket` request with the header `X-Tigris-Enable-Snapshot: true`.

The `@tigrisdata/agent-kit` package wraps this workflow as `createForks()`. It snapshots the source bucket and creates one or more forks in a single call. Passing `credentials: { role: 'Editor' }` also creates a scoped access key per fork, so each sandbox can read and write only its own fork bucket instead of the full account.

```typescript
import { createForks, teardownForks } from '@tigrisdata/agent-kit'
import { Daytona } from '@daytona/sdk'

const SOURCE_BUCKET = 'my-source-bucket'

// 1. Snapshot the source and create a fork with a scoped access key
const { data: forkSet, error } = await createForks(SOURCE_BUCKET, 1, {
  credentials: { role: 'Editor' },
})
if (error) throw error
const fork = forkSet.forks[0]

// 2. Launch the sandbox with the fork's scoped credentials
const daytona = new Daytona()
const sandbox = await daytona.create({
  snapshot: 'fuse-tigris',
  envVars: {
    AWS_ACCESS_KEY_ID: fork.credentials!.accessKeyId,
    AWS_SECRET_ACCESS_KEY: fork.credentials!.secretAccessKey,
  },
})

// 3. Mount the fork bucket
const mountPath = '/home/daytona/tigris'
await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(
  `mount-s3 --endpoint-url https://t3.storage.dev ${fork.bucket} ${mountPath}`,
)

try {
  const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
  console.log(response.result)
} finally {
  await daytona.delete(sandbox)
  await teardownForks(forkSet) // revokes the scoped key and deletes the fork bucket
}
```

To run the same workflow from a language without an `agent-kit` equivalent, use any S3 SDK and send the headers documented below. Send `X-Tigris-Snapshot: true` on `CreateBucket` for the source name, then capture `X-Tigris-Snapshot-Version` from the response. Next, send `CreateBucket` for the fork name with `X-Tigris-Fork-Source-Bucket` and `X-Tigris-Fork-Source-Bucket-Snapshot`. Mount the fork with the same `mount-s3` snippets shown above, replacing the bucket name with the fork bucket.

#### Reference: Tigris-specific headers

These headers drive snapshot and fork operations over the S3 API. Use them with any AWS SDK (boto3, aws-sdk-go-v2, aws-sdk-java-v2, aws-sdk-ruby) by attaching a request interceptor.

| Header                                     | Sent on                                   | Purpose                                                                        |
| ------------------------------------------ | ----------------------------------------- | ------------------------------------------------------------------------------ |
| **`X-Tigris-Enable-Snapshot: true`**       | **`CreateBucket`** (new source)           | Enable snapshots on a new bucket. Required before snapshotting it.             |
| **`X-Tigris-Snapshot: true`**              | **`CreateBucket`** (existing source name) | Take a snapshot of the bucket. Optional **`; name=<label>`** suffix labels it. |
| **`X-Tigris-Snapshot-Version`**            | Response to snapshot create               | Snapshot version ID returned to the caller — pass to fork creation.            |
| **`X-Tigris-Fork-Source-Bucket`**          | **`CreateBucket`** (new fork name)        | Source bucket to fork from.                                                    |
| **`X-Tigris-Fork-Source-Bucket-Snapshot`** | **`CreateBucket`** (new fork name)        | Source snapshot version to fork from.                                          |

Source: [**`tigrisdata/storage`**](https://github.com/tigrisdata/storage). See **`shared/headers.ts`** for the full header set.

## Mount a Supabase Storage bucket

Mount a Supabase Storage bucket with the same `mount-s3` tool used for S3. Supabase Storage is [S3-compatible ↗](https://supabase.com/docs/guides/storage/s3/compatibility) and serves each project at `https://<project_ref>.storage.supabase.co/storage/v1/s3`, so pass that endpoint with `--endpoint-url`, the project's region with `--region`, and `--force-path-style`. The path-style flag is required — Supabase serves all buckets from the project hostname rather than per-bucket subdomains, so `mount-s3`'s default virtual-hosted-style addressing (which prepends the bucket name to the endpoint hostname) fails during TLS negotiation.

**Credentials** — in the [Supabase dashboard ↗](https://supabase.com/dashboard/project/_/storage/s3), enable **S3 protocol connection** on your project's **Storage** > **S3** page and generate a pair of S3 access keys. Set `SUPABASE_PROJECT_REF` (the `<project_ref>` subdomain of the endpoint shown on that page), `SUPABASE_REGION` (the project's region, e.g. `us-east-1`), `SUPABASE_S3_ACCESS_KEY_ID`, and `SUPABASE_S3_SECRET_ACCESS_KEY` in your local environment. The snippets below pass the keys into the sandbox via `envVars` under the `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` names that `mount-s3` expects. S3 access keys grant full access to every bucket in the project and bypass [Row Level Security ↗](https://supabase.com/docs/guides/storage/security/access-control) policies, so treat them as server-side secrets.

### Pre-built snapshot

Build a snapshot with `mount-s3` preinstalled, then launch Supabase-enabled sandboxes from that snapshot. The mount flow matches S3 except for the Supabase `--endpoint-url`, `--region`, and `--force-path-style` flags, and startup stays fast because installation happens once during snapshot build.

#### Build a snapshot

Create a reusable snapshot that installs `mount-s3`. Because Supabase Storage is S3-compatible, this setup matches S3 and only the runtime mount command changes.


```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb "
    "&& rm /tmp/mount-s3.deb",
  )
)

daytona.snapshot.create(
    CreateSnapshotParams(name="fuse-supabase", image=image),
    on_logs=print,
)
```


```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' +
    '&& rm /tmp/mount-s3.deb',
)

await daytona.snapshot.create(
  { name: 'fuse-supabase', image },
  { onLogs: console.log },
)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

image = Daytona::Image
  .base('daytonaio/sandbox')
  .run_commands(
    'sudo apt-get update ' \
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
    '&& wget -O /tmp/mount-s3.deb ' \
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
    '&& sudo apt-get install -y /tmp/mount-s3.deb ' \
    '&& rm /tmp/mount-s3.deb'
  )

daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(name: 'fuse-supabase', image: image),
  on_logs: proc { |chunk| print(chunk) }
)
```


```go
import (
    "context"
    "fmt"
    "log"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

image := daytona.Base("daytonaio/sandbox").
    Run("sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget").
    Run(`arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && ` +
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && ` +
        `sudo apt-get install -y /tmp/mount-s3.deb && rm /tmp/mount-s3.deb`)

_, logChan, err := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
    Name:  "fuse-supabase",
    Image: image,
})
if err != nil {
    log.Fatal(err)
}
for line := range logChan {
    fmt.Print(line)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Image;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Image image = Image.base("daytonaio/sandbox")
                .runCommands(
                    "sudo apt-get update "
                        + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget",
                    "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                        + "&& wget -O /tmp/mount-s3.deb "
                        + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                        + "&& sudo apt-get install -y /tmp/mount-s3.deb "
                        + "&& rm /tmp/mount-s3.deb"
                );

            daytona.snapshot().create("fuse-supabase", image, System.out::println);
        }
    }
}
```


#### Launch and mount

Pass your Supabase S3 access keys into the sandbox as `AWS_*` environment variables, then mount with the project's S3 endpoint, region, and path-style addressing. This keeps authentication compatible with `mount-s3` while targeting your Supabase project.


```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

# S3 endpoint, region, and access keys live in your Supabase dashboard under Storage > S3
project_ref = os.environ["SUPABASE_PROJECT_REF"]
region = os.environ["SUPABASE_REGION"]

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-supabase",
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["SUPABASE_S3_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["SUPABASE_S3_SECRET_ACCESS_KEY"],
        },
    )
)

mount_path = "/home/daytona/supabase"

sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(
    f"mount-s3 --endpoint-url https://{project_ref}.storage.supabase.co/storage/v1/s3 "
    f"--region {region} --force-path-style "
    f"my-supabase-bucket {mount_path}"
)

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

// S3 endpoint, region, and access keys live in your Supabase dashboard under Storage > S3
const projectRef = process.env.SUPABASE_PROJECT_REF!
const region = process.env.SUPABASE_REGION!

const sandbox = await daytona.create({
  snapshot: 'fuse-supabase',
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.SUPABASE_S3_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.SUPABASE_S3_SECRET_ACCESS_KEY!,
  },
})

const mountPath = '/home/daytona/supabase'

await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(
  `mount-s3 --endpoint-url https://${projectRef}.storage.supabase.co/storage/v1/s3 ` +
    `--region ${region} --force-path-style ` +
    `my-supabase-bucket ${mountPath}`,
)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

# S3 endpoint, region, and access keys live in your Supabase dashboard under Storage > S3
project_ref = ENV.fetch('SUPABASE_PROJECT_REF')
region = ENV.fetch('SUPABASE_REGION')

sandbox = daytona.create(
  Daytona::CreateSandboxFromSnapshotParams.new(
    snapshot: 'fuse-supabase',
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('SUPABASE_S3_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('SUPABASE_S3_SECRET_ACCESS_KEY')
    }
  )
)

mount_path = '/home/daytona/supabase'

sandbox.process.exec(command: "mkdir -p #{mount_path}")
sandbox.process.exec(
  command: "mount-s3 --endpoint-url https://#{project_ref}.storage.supabase.co/storage/v1/s3 " \
           "--region #{region} --force-path-style " \
           "my-supabase-bucket #{mount_path}"
)

response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

// S3 endpoint, region, and access keys live in your Supabase dashboard under Storage > S3
projectRef := os.Getenv("SUPABASE_PROJECT_REF")
region := os.Getenv("SUPABASE_REGION")

sandbox, err := client.Create(ctx, types.SnapshotParams{
    Snapshot: "fuse-supabase",
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("SUPABASE_S3_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("SUPABASE_S3_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

mountPath := "/home/daytona/supabase"

if _, err := sandbox.Process.ExecuteCommand(ctx, "mkdir -p "+mountPath); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mount-s3 --endpoint-url https://"+projectRef+".storage.supabase.co/storage/v1/s3 "+
        "--region "+region+" --force-path-style "+
        "my-supabase-bucket "+mountPath); err != nil {
    log.Fatal(err)
}

response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            // S3 endpoint, region, and access keys live in your Supabase dashboard under Storage > S3
            String projectRef = System.getenv("SUPABASE_PROJECT_REF");
            String region = System.getenv("SUPABASE_REGION");

            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setSnapshot("fuse-supabase");
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("SUPABASE_S3_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("SUPABASE_S3_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            String mountPath = "/home/daytona/supabase";

            sandbox.getProcess().executeCommand("mkdir -p " + mountPath);
            sandbox.getProcess().executeCommand(
                "mount-s3 --endpoint-url https://" + projectRef + ".storage.supabase.co/storage/v1/s3 "
                    + "--region " + region + " --force-path-style "
                    + "my-supabase-bucket " + mountPath);

            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```


### Runtime install

Start from a default sandbox, install `mount-s3` during startup, then mount with the Supabase `--endpoint-url`, `--region`, and `--force-path-style` flags. This path is convenient for prototyping or one-off tasks, but each new sandbox repeats package installation.


```python
import os
from daytona import CreateSandboxBaseParams, Daytona

daytona = Daytona()

project_ref = os.environ["SUPABASE_PROJECT_REF"]
region = os.environ["SUPABASE_REGION"]

sandbox = daytona.create(
    CreateSandboxBaseParams(
        env_vars={
            "AWS_ACCESS_KEY_ID": os.environ["SUPABASE_S3_ACCESS_KEY_ID"],
            "AWS_SECRET_ACCESS_KEY": os.environ["SUPABASE_S3_SECRET_ACCESS_KEY"],
        },
    )
)

# Install mount-s3
sandbox.process.exec(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"
)
sandbox.process.exec(
    'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" '
    '&& wget -O /tmp/mount-s3.deb '
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" '
    "&& sudo apt-get install -y /tmp/mount-s3.deb"
)

# Mount with Supabase endpoint
mount_path = "/home/daytona/supabase"
sandbox.process.exec(
    f"mkdir -p {mount_path} && "
    f"mount-s3 --endpoint-url https://{project_ref}.storage.supabase.co/storage/v1/s3 "
    f"--region {region} --force-path-style "
    f"my-supabase-bucket {mount_path}"
)
response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const projectRef = process.env.SUPABASE_PROJECT_REF!
const region = process.env.SUPABASE_REGION!

const sandbox = await daytona.create({
  envVars: {
    AWS_ACCESS_KEY_ID: process.env.SUPABASE_S3_ACCESS_KEY_ID!,
    AWS_SECRET_ACCESS_KEY: process.env.SUPABASE_S3_SECRET_ACCESS_KEY!,
  },
})

// Install mount-s3
await sandbox.process.executeCommand(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget',
)
await sandbox.process.executeCommand(
  'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' +
    '&& wget -O /tmp/mount-s3.deb ' +
    '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' +
    '&& sudo apt-get install -y /tmp/mount-s3.deb',
)

// Mount with Supabase endpoint
const mountPath = '/home/daytona/supabase'
await sandbox.process.executeCommand(
  `mkdir -p ${mountPath} && ` +
    `mount-s3 --endpoint-url https://${projectRef}.storage.supabase.co/storage/v1/s3 ` +
    `--region ${region} --force-path-style ` +
    `my-supabase-bucket ${mountPath}`,
)
const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new

project_ref = ENV.fetch('SUPABASE_PROJECT_REF')
region = ENV.fetch('SUPABASE_REGION')

sandbox = daytona.create(
  Daytona::CreateSandboxBaseParams.new(
    env_vars: {
      'AWS_ACCESS_KEY_ID' => ENV.fetch('SUPABASE_S3_ACCESS_KEY_ID'),
      'AWS_SECRET_ACCESS_KEY' => ENV.fetch('SUPABASE_S3_SECRET_ACCESS_KEY')
    }
  )
)

# Install mount-s3
sandbox.process.exec(
  command: 'sudo apt-get update ' \
           '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget'
)
sandbox.process.exec(
  command: 'arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" ' \
           '&& wget -O /tmp/mount-s3.deb ' \
           '"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" ' \
           '&& sudo apt-get install -y /tmp/mount-s3.deb'
)

# Mount with Supabase endpoint
mount_path = '/home/daytona/supabase'
sandbox.process.exec(
  command: "mkdir -p #{mount_path} && " \
           "mount-s3 --endpoint-url https://#{project_ref}.storage.supabase.co/storage/v1/s3 " \
           "--region #{region} --force-path-style " \
           "my-supabase-bucket #{mount_path}"
)
response = sandbox.process.exec(command: "ls #{mount_path}")
puts response.result
```


```go
import (
    "context"
    "fmt"
    "log"
    "os"

    "github.com/daytona/clients/sdk-go/pkg/daytona"
    "github.com/daytona/clients/sdk-go/pkg/types"
)

ctx := context.Background()
client, err := daytona.NewClient()
if err != nil {
    log.Fatal(err)
}

projectRef := os.Getenv("SUPABASE_PROJECT_REF")
region := os.Getenv("SUPABASE_REGION")

sandbox, err := client.Create(ctx, types.SnapshotParams{
    SandboxBaseParams: types.SandboxBaseParams{
        EnvVars: map[string]string{
            "AWS_ACCESS_KEY_ID":     os.Getenv("SUPABASE_S3_ACCESS_KEY_ID"),
            "AWS_SECRET_ACCESS_KEY": os.Getenv("SUPABASE_S3_SECRET_ACCESS_KEY"),
        },
    },
})
if err != nil {
    log.Fatal(err)
}

// Install mount-s3
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "sudo apt-get update && sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget"); err != nil {
    log.Fatal(err)
}
if _, err := sandbox.Process.ExecuteCommand(ctx,
    `arch="$(dpkg --print-architecture | sed s/amd64/x86_64/)" && `+
        `wget -O /tmp/mount-s3.deb "https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb" && `+
        `sudo apt-get install -y /tmp/mount-s3.deb`); err != nil {
    log.Fatal(err)
}

// Mount with Supabase endpoint
mountPath := "/home/daytona/supabase"
if _, err := sandbox.Process.ExecuteCommand(ctx,
    "mkdir -p "+mountPath+" && "+
        "mount-s3 --endpoint-url https://"+projectRef+".storage.supabase.co/storage/v1/s3 "+
        "--region "+region+" --force-path-style "+
        "my-supabase-bucket "+mountPath); err != nil {
    log.Fatal(err)
}
response, err := sandbox.Process.ExecuteCommand(ctx, "ls "+mountPath)
if err != nil {
    log.Fatal(err)
}
fmt.Println(response.Result)
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.util.Map;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            String projectRef = System.getenv("SUPABASE_PROJECT_REF");
            String region = System.getenv("SUPABASE_REGION");

            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setEnvVars(Map.of(
                "AWS_ACCESS_KEY_ID", System.getenv("SUPABASE_S3_ACCESS_KEY_ID"),
                "AWS_SECRET_ACCESS_KEY", System.getenv("SUPABASE_S3_SECRET_ACCESS_KEY")
            ));
            Sandbox sandbox = daytona.create(params);

            // Install mount-s3
            sandbox.getProcess().executeCommand(
                "sudo apt-get update "
                    + "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates wget");
            sandbox.getProcess().executeCommand(
                "arch=\"$(dpkg --print-architecture | sed s/amd64/x86_64/)\" "
                    + "&& wget -O /tmp/mount-s3.deb "
                    + "\"https://s3.amazonaws.com/mountpoint-s3-release/latest/${arch}/mount-s3.deb\" "
                    + "&& sudo apt-get install -y /tmp/mount-s3.deb");

            // Mount with Supabase endpoint
            String mountPath = "/home/daytona/supabase";
            sandbox.getProcess().executeCommand(
                "mkdir -p " + mountPath + " && "
                    + "mount-s3 --endpoint-url https://" + projectRef + ".storage.supabase.co/storage/v1/s3 "
                    + "--region " + region + " --force-path-style "
                    + "my-supabase-bucket " + mountPath);

            ExecuteResponse response = sandbox.getProcess().executeCommand("ls " + mountPath);
            System.out.println(response.getResult());
        }
    }
}
```

## Mount a Google Cloud Storage bucket

Mount a GCS bucket using [gcsfuse ↗](https://github.com/GoogleCloudPlatform/gcsfuse) — Google's official FUSE client.

**Credentials** — `gcsfuse` reads a service account JSON key file. The snippets below read the key from a local path on your host and upload it into the sandbox via `sandbox.fs`.

:::note
Daytona's base image is Debian Trixie, but Google has not published a Trixie-specific gcsfuse repository yet. The `gcsfuse-bookworm` repo packages run cleanly on Trixie, so we use them below.
:::

### Pre-built snapshot

Build a snapshot with `gcsfuse` preinstalled, then launch all GCS-enabled sandboxes from that snapshot.

```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends ca-certificates curl gnupg",
    "sudo mkdir -p /etc/apt/keyrings "
    "&& curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg "
    "| sudo gpg --dearmor -o /etc/apt/keyrings/gcsfuse.gpg",
    'echo "deb [signed-by=/etc/apt/keyrings/gcsfuse.gpg] '
    'https://packages.cloud.google.com/apt gcsfuse-bookworm main" '
    "| sudo tee /etc/apt/sources.list.d/gcsfuse.list",
    "sudo apt-get update && sudo apt-get install -y gcsfuse",
  )
)

daytona.snapshot.create(CreateSnapshotParams(name="fuse-gcs", image=image), on_logs=print)
```

```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends ca-certificates curl gnupg',
  'sudo mkdir -p /etc/apt/keyrings ' +
    '&& curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg ' +
    '| sudo gpg --dearmor -o /etc/apt/keyrings/gcsfuse.gpg',
  'echo "deb [signed-by=/etc/apt/keyrings/gcsfuse.gpg] ' +
    'https://packages.cloud.google.com/apt gcsfuse-bookworm main" ' +
    '| sudo tee /etc/apt/sources.list.d/gcsfuse.list',
  'sudo apt-get update && sudo apt-get install -y gcsfuse',
)

await daytona.snapshot.create({ name: 'fuse-gcs', image }, { onLogs: console.log })
```

Ruby, Go, and Java follow the same `Image.base("daytonaio/sandbox")` + apt/gpg/gcsfuse install-step pattern shown for S3/R2/Tigris/Supabase above.

#### Launch and mount

`gcsfuse` authenticates with a service account JSON key. Upload it into the sandbox via `sandbox.fs` and point `gcsfuse` at it with `--key-file`.

```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()
service_account_key = os.environ["GCS_SERVICE_ACCOUNT_KEY"].encode()

sandbox = daytona.create(CreateSandboxFromSnapshotParams(snapshot="fuse-gcs"))

mount_path = "/home/daytona/gcs"
key_path = "/home/daytona/.gcs-key.json"

sandbox.fs.upload_file(service_account_key, key_path)
sandbox.process.exec(f"chmod 600 {key_path}")
sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(f"gcsfuse --key-file={key_path} my-gcs-bucket {mount_path}")

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```

```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()
const serviceAccountKey = Buffer.from(process.env.GCS_SERVICE_ACCOUNT_KEY!)

const sandbox = await daytona.create({ snapshot: 'fuse-gcs' })

const mountPath = '/home/daytona/gcs'
const keyPath = '/home/daytona/.gcs-key.json'

await sandbox.fs.uploadFile(serviceAccountKey, keyPath)
await sandbox.process.executeCommand(`chmod 600 ${keyPath}`)
await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(`gcsfuse --key-file=${keyPath} my-gcs-bucket ${mountPath}`)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```

Ruby, Go, and Java: upload the service-account-key bytes via the SDK's filesystem upload call, `chmod 600` the key path, then run `gcsfuse --key-file=<path> my-gcs-bucket <mount_path>` via the process/exec call — same shape as the S3 examples above.

### Runtime install

Start from a default sandbox, install `gcsfuse` from the bookworm repo at startup (same apt/gpg steps as the pre-built snapshot above, run via `process.exec` instead of `Image.run_commands`), then upload the key and mount as shown above. Slower cold start, no snapshot to maintain.

## Mount an Azure Blob container

Mount an Azure Blob container using [blobfuse2 ↗](https://github.com/Azure/azure-storage-fuse) — Microsoft's official FUSE client.

**Credentials** — set `AZURE_STORAGE_ACCOUNT`, `AZURE_STORAGE_CONTAINER`, and `AZURE_STORAGE_ACCOUNT_KEY` in your local environment. `blobfuse2` reads its configuration from a YAML file built with these values.

:::caution
Daytona's base image is Debian Trixie. Microsoft's `blobfuse2` Bookworm binary links against `libfuse3.so.3`, but Trixie's `fuse3` package bumped the SONAME to `.4`, so `libfuse3.so.3` is missing on disk. The snapshot recipe below creates a compatibility symlink. Without it, `blobfuse2` fails with `libfuse3.so.3: cannot open shared object file`.
:::

### Pre-built snapshot

```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends ca-certificates curl gnupg wget",
    # Microsoft's apt repo (use bookworm packages on Trixie)
    "wget -qO- https://packages.microsoft.com/keys/microsoft.asc "
    "| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg",
    'echo "deb [arch=$(dpkg --print-architecture) '
    'signed-by=/etc/apt/trusted.gpg.d/microsoft.gpg] '
    'https://packages.microsoft.com/debian/12/prod bookworm main" '
    "| sudo tee /etc/apt/sources.list.d/microsoft-prod.list",
    "sudo apt-get update && sudo apt-get install -y blobfuse2 fuse3",
    # libfuse3.so.3 compat symlink for Trixie (see :::caution above)
    'src=$(find /usr/lib /lib -name "libfuse3.so.3.*" -type f 2>/dev/null '
    "| sort -V | tail -1) "
    '&& sudo ln -sfn "$src" "$(dirname "$src")/libfuse3.so.3" '
    "&& sudo ldconfig",
    "sudo touch /etc/fuse.conf "
    '&& grep -qxF "user_allow_other" /etc/fuse.conf '
    '|| echo "user_allow_other" | sudo tee -a /etc/fuse.conf',
  )
)

daytona.snapshot.create(CreateSnapshotParams(name="fuse-azure", image=image), on_logs=print)
```

```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends ca-certificates curl gnupg wget',
  'wget -qO- https://packages.microsoft.com/keys/microsoft.asc ' +
    '| sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg',
  'echo "deb [arch=$(dpkg --print-architecture) ' +
    'signed-by=/etc/apt/trusted.gpg.d/microsoft.gpg] ' +
    'https://packages.microsoft.com/debian/12/prod bookworm main" ' +
    '| sudo tee /etc/apt/sources.list.d/microsoft-prod.list',
  'sudo apt-get update && sudo apt-get install -y blobfuse2 fuse3',
  'src=$(find /usr/lib /lib -name "libfuse3.so.3.*" -type f 2>/dev/null ' +
    '| sort -V | tail -1) ' +
    '&& sudo ln -sfn "$src" "$(dirname "$src")/libfuse3.so.3" ' +
    '&& sudo ldconfig',
  'sudo touch /etc/fuse.conf ' +
    '&& grep -qxF "user_allow_other" /etc/fuse.conf ' +
    '|| echo "user_allow_other" | sudo tee -a /etc/fuse.conf',
)

await daytona.snapshot.create({ name: 'fuse-azure', image }, { onLogs: console.log })
```

Ruby, Go, and Java follow the same install-step pattern.

#### Launch and mount

The YAML config tells `blobfuse2` three things: **where to connect** (the `azstorage:` block), **what to enable** (the `components:` list — libfuse, block_cache, attr_cache, azstorage), and **how to log**. In Azure terminology, a "container" is the equivalent of an S3 bucket.

```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()
sandbox = daytona.create(CreateSandboxFromSnapshotParams(snapshot="fuse-azure"))

mount_path = "/home/daytona/azure"
config_path = "/home/daytona/.blobfuse2.yaml"

account = os.environ["AZURE_STORAGE_ACCOUNT"]
container = os.environ["AZURE_STORAGE_CONTAINER"]
account_key = os.environ["AZURE_STORAGE_ACCOUNT_KEY"]

config = f"""\
allow-other: true
logging:
  type: syslog
  level: log_warning
components:
  - libfuse
  - block_cache
  - attr_cache
  - azstorage
azstorage:
  type: block
  account-name: {account}
  container: {container}
  endpoint: https://{account}.blob.core.windows.net
  auth-type: key
  account-key: {account_key}
"""

sandbox.fs.upload_file(config.encode(), config_path)
sandbox.process.exec(f"chmod 600 {config_path}")
sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(f"blobfuse2 mount --config-file={config_path} {mount_path}")

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```

```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()
const sandbox = await daytona.create({ snapshot: 'fuse-azure' })

const mountPath = '/home/daytona/azure'
const configPath = '/home/daytona/.blobfuse2.yaml'

const account = process.env.AZURE_STORAGE_ACCOUNT!
const container = process.env.AZURE_STORAGE_CONTAINER!
const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY!

const config = `allow-other: true
logging:
  type: syslog
  level: log_warning
components:
  - libfuse
  - block_cache
  - attr_cache
  - azstorage
azstorage:
  type: block
  account-name: ${account}
  container: ${container}
  endpoint: https://${account}.blob.core.windows.net
  auth-type: key
  account-key: ${accountKey}
`

await sandbox.fs.uploadFile(Buffer.from(config), configPath)
await sandbox.process.executeCommand(`chmod 600 ${configPath}`)
await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(`blobfuse2 mount --config-file=${configPath} ${mountPath}`)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```

Ruby, Go, and Java: build the same YAML string, upload it via the SDK's filesystem call, `chmod 600`, then run `blobfuse2 mount --config-file=<path> <mount_path>`.

### Runtime install

Start from a default sandbox, install `blobfuse2` + the `libfuse3.so.3` compat symlink at startup (same steps as the pre-built snapshot above, via `process.exec`), then write the YAML config and mount as shown above.

## Mount a Box folder

Mount a Box folder using [rclone](https://rclone.org/box/) -- Box has no official Linux FUSE client, and the rclone Box backend is the standard way to expose Box content as a mounted directory.

rclone supports two Box authentication methods: OAuth (any Box account, one-time browser authorization on the local machine) and JWT server authentication (enterprise-owned Platform Apps, browser-free, requires a Box admin to authorize the app).

### Install rclone

Debian packaged rclone lags far behind current releases, so use the official rclone install script.

```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends ca-certificates curl fuse3 unzip",
    "curl -fsSL https://rclone.org/install.sh | sudo bash",
  )
)

daytona.snapshot.create(CreateSnapshotParams(name="fuse-box", image=image), on_logs=print)
```

```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends ca-certificates curl fuse3 unzip',
  'curl -fsSL https://rclone.org/install.sh | sudo bash',
)

await daytona.snapshot.create({ name: 'fuse-box', image }, { onLogs: console.log })
```

To skip snapshot management, install rclone at sandbox startup instead (same two commands via process.exec on a default sandbox) -- the mount flow is the same either way.

### Mount with OAuth

Authorize once on the local machine with a browser; every sandbox then mounts headlessly with the resulting token.

Credentials -- create an [OAuth 2.0 app](https://developer.box.com/guides/authentication/oauth2/oauth2-setup/) in the Box Developer Console with redirect URI http://127.0.0.1:53682/ (the fixed local port rclone listens on). Install rclone locally and run:

```bash
rclone authorize box YOUR_CLIENT_ID YOUR_CLIENT_SECRET
```

A browser window opens for Box login; rclone then prints a single-line token JSON. Set BOX_CLIENT_ID, BOX_CLIENT_SECRET, and BOX_RCLONE_TOKEN (the printed JSON) locally. Running rclone authorize box with no arguments instead authorizes the built-in rclone Box app (omit client_id/secret, pass only the token) -- but all rclone users worldwide then share that app rate limit, so use a dedicated app for production.

:::note
Box rotates the refresh token on every renewal, and the rotated token lives only inside the sandbox rclone config. Generate a separate token per concurrently running sandbox. For fleets sharing one identity, prefer JWT server auth below.
:::

#### Launch and mount

The --non-interactive flag fails fast on a bad token instead of waiting for a browser login that can never happen inside a sandbox; --vfs-cache-mode writes is required because Box only accepts whole-file uploads.

```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-box",
        env_vars={
            "BOX_CLIENT_ID": os.environ["BOX_CLIENT_ID"],
            "BOX_CLIENT_SECRET": os.environ["BOX_CLIENT_SECRET"],
            "BOX_RCLONE_TOKEN": os.environ["BOX_RCLONE_TOKEN"],
        },
    )
)

mount_path = "/home/daytona/box"

sandbox.process.exec(
    'rclone config create mybox box client_id="$BOX_CLIENT_ID" '
    'client_secret="$BOX_CLIENT_SECRET" token="$BOX_RCLONE_TOKEN" --non-interactive'
)
sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(f"rclone mount mybox: {mount_path} --daemon --vfs-cache-mode writes")

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```

```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const sandbox = await daytona.create({
  snapshot: 'fuse-box',
  envVars: {
    BOX_CLIENT_ID: process.env.BOX_CLIENT_ID!,
    BOX_CLIENT_SECRET: process.env.BOX_CLIENT_SECRET!,
    BOX_RCLONE_TOKEN: process.env.BOX_RCLONE_TOKEN!,
  },
})

const mountPath = '/home/daytona/box'

await sandbox.process.executeCommand(
  'rclone config create mybox box client_id="$BOX_CLIENT_ID" ' +
    'client_secret="$BOX_CLIENT_SECRET" token="$BOX_RCLONE_TOKEN" --non-interactive',
)
await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(`rclone mount mybox: ${mountPath} --daemon --vfs-cache-mode writes`)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```

### Mount with JWT server authentication

Fully non-interactive -- the app authenticates with a signed assertion instead of a user login, suiting fleets of sandboxes sharing one identity. Requires an app owned by a Box enterprise (a free developer account works; a personal account fails with enterpriseID 0).

Credentials -- create a [Platform App with JWT authentication](https://developer.box.com/guides/authentication/jwt/jwt-setup/) (select JWT, not Client Credentials Grant -- the rclone Box backend only supports JWT for server auth). Generate a Public/Private Keypair (downloads the app config JSON; requires 2FA), have a Box admin authorize the app for the enterprise, then set BOX_CONFIG_JSON locally to the full JSON contents.

:::note
A JWT app authenticates as a service account with its own content tree -- invite its email (shown under General Settings) as a collaborator on the folder to mount, or append impersonate=user@example.com to rclone config create to act as a specific managed user.
:::

#### Launch and mount

```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()
box_config = os.environ["BOX_CONFIG_JSON"].encode()

sandbox = daytona.create(CreateSandboxFromSnapshotParams(snapshot="fuse-box"))

mount_path = "/home/daytona/box"
config_path = "/home/daytona/.box-config.json"

sandbox.fs.upload_file(box_config, config_path)
sandbox.process.exec(f"chmod 600 {config_path}")
sandbox.process.exec(
    f"rclone config create mybox box box_config_file={config_path} "
    "box_sub_type=enterprise --non-interactive"
)
sandbox.process.exec(f"mkdir -p {mount_path}")
sandbox.process.exec(f"rclone mount mybox: {mount_path} --daemon --vfs-cache-mode writes")

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```

```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()
const boxConfig = Buffer.from(process.env.BOX_CONFIG_JSON!)

const sandbox = await daytona.create({ snapshot: 'fuse-box' })

const mountPath = '/home/daytona/box'
const configPath = '/home/daytona/.box-config.json'

await sandbox.fs.uploadFile(boxConfig, configPath)
await sandbox.process.executeCommand(`chmod 600 ${configPath}`)
await sandbox.process.executeCommand(
  `rclone config create mybox box box_config_file=${configPath} ` +
    'box_sub_type=enterprise --non-interactive',
)
await sandbox.process.executeCommand(`mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(`rclone mount mybox: ${mountPath} --daemon --vfs-cache-mode writes`)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```

Ruby, Go, and Java for both auth paths: upload or build the config the same way via the SDK, then run the same rclone config create / rclone mount commands via the process/exec call.

## Mount an Archil disk

[Archil](https://archil.com) is an infinite, elastic, POSIX file system that automatically synchronizes to object storage like S3, R2, and Azure Blob. Use Archil when a bucket needs to be mounted to a Daytona sandbox with higher out-of-the-box performance than traditional FUSE mounts, achieved via shared SSD read and write caching in front of the object storage bucket. Archil disks are mounted as regular directories, scale to whatever the sandbox writes (pay only for what is used), and can be [mounted by many sandboxes at once](https://docs.archil.com/concepts/shared-disks), making them a natural fit for parallel agents that share state.

Credentials — set `ARCHIL_MOUNT_TOKEN` (a disk-scoped [mount token](https://docs.archil.com/concepts/disk-users#disk-token-authorization) generated from the disk Details page in the [Archil console](https://console.archil.com)), `ARCHIL_REGION` (the disk region, e.g. `aws-us-east-1`), and `ARCHIL_DISK` (the owner-qualified disk name, e.g. `myorg/my-disk`, or disk ID like `dsk-0123456789abcdef`) in the local environment.

### Pre-built snapshot

The `daytonaio/sandbox` base image ships Debian Trixie which does not include `libfuse2`, and the `archil` CLI links against it, so apt-install it before the Archil installer. On Trixie the package is named `libfuse2t64`; installing `libfuse2` also works because it is a transitional package that pulls in `libfuse2t64`.

```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "sudo apt-get update "
    "&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates",
    "curl -fsSL https://archil.com/install | sh",
  )
)

daytona.snapshot.create(
    CreateSnapshotParams(name="fuse-archil", image=image),
    on_logs=lambda chunk: print(chunk, end="", flush=True),
)
```

```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'sudo apt-get update ' +
    '&& sudo apt-get install -y --no-install-recommends libfuse2 ca-certificates',
  'curl -fsSL https://archil.com/install | sh',
)

await daytona.snapshot.create({ name: 'fuse-archil', image }, { onLogs: console.log })
```

#### Launch and mount

Pass `ARCHIL_MOUNT_TOKEN`, `ARCHIL_REGION`, and `ARCHIL_DISK` to the sandbox via `envVars`. The code then mounts the disk at `/home/daytona/archil` and hands ownership to the `daytona` user so non-root processes can read and write through the mount. The `chown` step works on exclusive (non-shared) mounts only; on mounts created with `--shared` or `--read-only` it fails with "Read-only file system" (see Shared and read-only mounts below).

```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

mount_path = "/home/daytona/archil"

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-archil",
        env_vars={
            "ARCHIL_MOUNT_TOKEN": os.environ["ARCHIL_MOUNT_TOKEN"],
            "ARCHIL_REGION": os.environ["ARCHIL_REGION"],
            "ARCHIL_DISK": os.environ["ARCHIL_DISK"],
        },
    )
)

sandbox.process.exec(f"sudo mkdir -p {mount_path}")
sandbox.process.exec(
    f"sudo --preserve-env=ARCHIL_MOUNT_TOKEN archil mount "
    f"$ARCHIL_DISK {mount_path} --region $ARCHIL_REGION"
)
# Exclusive mounts only; on --shared or --read-only mounts this fails with "Read-only file system"
sandbox.process.exec(f"sudo chown daytona:daytona {mount_path}")

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```

```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const mountPath = '/home/daytona/archil'

const sandbox = await daytona.create({
  snapshot: 'fuse-archil',
  envVars: {
    ARCHIL_MOUNT_TOKEN: process.env.ARCHIL_MOUNT_TOKEN!,
    ARCHIL_REGION: process.env.ARCHIL_REGION!,
    ARCHIL_DISK: process.env.ARCHIL_DISK!,
  },
})

await sandbox.process.executeCommand(`sudo mkdir -p ${mountPath}`)
await sandbox.process.executeCommand(
  `sudo --preserve-env=ARCHIL_MOUNT_TOKEN archil mount ` +
    `$ARCHIL_DISK ${mountPath} --region $ARCHIL_REGION`,
)
// Exclusive mounts only; on --shared or --read-only mounts this fails with "Read-only file system"
await sandbox.process.executeCommand(`sudo chown daytona:daytona ${mountPath}`)

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```

To let multiple sandboxes mount the same disk concurrently, add `--shared` to `archil mount`. Shared mounts change how permissions and writes behave; see Shared and read-only mounts below.

### Runtime install

Start from a default sandbox and install the `archil` CLI during startup before mounting the disk (same apt/curl steps as the pre-built snapshot above, via `process.exec`), then mount and chown as shown above. Slower cold start per sandbox, no snapshot to maintain.

### Shared and read-only mounts

The `--shared` and `--read-only` flags produce the same mount behavior: the entire mount is read-only, including `chmod` and `chown`, until `archil checkout <path>` grants a write delegation for that path. Two consequences:

- `sudo chown daytona:daytona <mountPath>` fails with "Read-only file system" on any `--shared` or `--read-only` mount. On a writable shared mount: run `sudo archil checkout <mountPath>`, then `chown`, then `sudo archil checkin <mountPath>`.
- Ownership and permissions come from the metadata stored on the Archil disk, not from the mount. If a root process wrote files with a restrictive umask, every mount shows them as `root:root` with mode `600`, and the `daytona` user cannot read them.

Fix options:

1. Fix permissions at the source (recommended). Write with `umask 022` or run `chmod -R a+rX` after writing. For existing data, apply a one-time fix from any client with a writable shared mount:

```bash
sudo --preserve-env=ARCHIL_MOUNT_TOKEN archil mount "$ARCHIL_DISK" /mnt/fix --region "$ARCHIL_REGION" --shared
sudo archil checkout /mnt/fix/data
sudo chmod -R a+rX /mnt/fix/data
sudo archil checkin /mnt/fix/data
```

The permission bits persist on the disk, so every subsequent read-only mount shows the corrected modes.

2. Re-export with bindfs (when the source data cannot be changed). Inside the sandbox, mount a read-only view of the Archil mount that remaps ownership to the `daytona` user:

```bash
sudo apt-get install -y bindfs
mkdir -p /home/daytona/archil-view
sudo bindfs --force-user=daytona --force-group=daytona --perms=a+rX \
  /home/daytona/archil /home/daytona/archil-view
```

The `archil` CLI requires root to mount and has no uid, gid, or umask override flags, so there is no way to remap ownership at mount time.

### Common pitfalls

Archil works on Tier 3 and Tier 4 sandboxes with default network settings (full egress) without additional configuration. The following failure modes look like Daytona blocking egress but have other causes:

- Missing `libfuse2`. Install `libfuse2t64` (the Trixie package name; `libfuse2` is a transitional package that pulls it in) before running the Archil installer, or bake both into a pre-built snapshot.
- Egress allowlists break Archil. A sandbox with a `domainAllowList` cannot mount Archil disks: the Archil control plane is reached as a bare IP address on port `8100`, which a domain allowlist cannot express. The installer also downloads from `s3.amazonaws.com/archil-client/`, which must be reachable at install time. A `networkAllowList` (CIDR) can pin Archil mount and control IP addresses, but those addresses change, so this is fragile and not recommended. Use full egress for sandboxes that mount Archil disks.
- `api.archil.com` is not a valid endpoint. The hostname does not resolve (NXDOMAIN). Archil endpoints are region-specific; for `aws-us-east-1` they are `mount.green.us-east-1.aws.prod.archil.com:8100` and `control.green.us-east-1.aws.prod.archil.com:443`. See [Archil troubleshooting](https://docs.archil.com/reference/troubleshooting).
- The disk is exclusively mounted elsewhere. An exclusive mount holds a delegation lock on the disk. Mounting from another sandbox fails until the first client unmounts or runs `archil checkin`, or the new mount passes `--shared` (or `--force` to break a stale lock). This is an Archil delegation conflict, not an egress failure.

## Mount a MesaFS filesystem

[MesaFS](https://mesa.dev) is an agent-native versioned filesystem from Mesa, purpose-built for the same workloads Daytona sandboxes run — parallel agent swarms, shared working memory, structured artifacts, and long-lived state across runs. With MesaFS, instead of mounting a cloud bucket, a Mesa **repository** is mounted: a Git-compatible versioned working directory with sub-50ms reads/writes, instant fork/branch operations, and unlimited concurrent writers.

The Mesa setup follows the same pattern as the bucket providers but uses the Mesa CLI rather than a FUSE-specific tool: install the CLI in the sandbox, authenticate with an API key, and run `mesa mount --daemonize` to mount repos at `/home/daytona/mesa/mnt/<org>/<repo>`.

Credentials — set `MESA_API_KEY` and `MESA_ORG` (the Mesa organization slug) in the local environment.

### Pre-built snapshot

```python
from daytona import CreateSnapshotParams, Daytona, Image

daytona = Daytona()

image = (
  Image.base("daytonaio/sandbox")
  .run_commands(
    "curl -fsSL https://mesa.dev/install.sh | sh",
    "sudo sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf",
  )
)

daytona.snapshot.create(
    CreateSnapshotParams(name="fuse-mesa", image=image),
    on_logs=lambda chunk: print(chunk, end="", flush=True),
)
```

```typescript
import { Daytona, Image } from '@daytona/sdk'

const daytona = new Daytona()

const image = Image.base('daytonaio/sandbox').runCommands(
  'curl -fsSL https://mesa.dev/install.sh | sh',
  "sudo sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf",
)

await daytona.snapshot.create({ name: 'fuse-mesa', image }, { onLogs: console.log })
```

#### Launch and mount

Pass `MESA_API_KEY` and the Mesa organization slug to the sandbox via `envVars`. The code then writes a TOML config into the sandbox, authenticates the Mesa CLI, and mounts repos at `/home/daytona/mesa/mnt/<org>/<repo>`.

```python
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona

daytona = Daytona()

org = os.environ["MESA_ORG"]
repo = "my-workspace"
mount_path = f"/home/daytona/mesa/mnt/{org}/{repo}"
config_path = "/home/daytona/.config/mesa/config.toml"

sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-mesa",
        env_vars={
            "MESA_API_KEY": os.environ["MESA_API_KEY"],
            "MESA_ORG": org,
        },
    )
)

config = f'''mount-point = "/home/daytona/mesa/mnt"

[secrets]
backend = "plaintext-file"

[organizations.{org}]
'''

sandbox.process.exec(f"mkdir -p $(dirname {config_path})")
sandbox.fs.upload_file(config.encode(), config_path)

sandbox.process.exec("mesa auth set-key --org $MESA_ORG $MESA_API_KEY")
sandbox.process.exec("mesa mount --daemonize")

response = sandbox.process.exec(f"ls {mount_path}")
print(response.result)
```

```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()

const org = process.env.MESA_ORG!
const repo = 'my-workspace'
const mountPath = `/home/daytona/mesa/mnt/${org}/${repo}`
const configPath = '/home/daytona/.config/mesa/config.toml'

const sandbox = await daytona.create({
  snapshot: 'fuse-mesa',
  envVars: {
    MESA_API_KEY: process.env.MESA_API_KEY!,
    MESA_ORG: org,
  },
})

const config = `mount-point = "/home/daytona/mesa/mnt"

[secrets]
backend = "plaintext-file"

[organizations.${org}]
`

await sandbox.process.executeCommand(`mkdir -p $(dirname ${configPath})`)
await sandbox.fs.uploadFile(Buffer.from(config), configPath)

await sandbox.process.executeCommand('mesa auth set-key --org $MESA_ORG $MESA_API_KEY')
await sandbox.process.executeCommand('mesa mount --daemonize')

const response = await sandbox.process.executeCommand(`ls ${mountPath}`)
console.log(response.result)
```

Ruby, Go, and Java: write the same TOML config via the SDK filesystem call, then run `mesa auth set-key --org $MESA_ORG $MESA_API_KEY` and `mesa mount --daemonize` via the process/exec call — same shape as above.

### Runtime install

Start from a default sandbox and install the Mesa CLI during startup (same `curl`/`sed` steps as the pre-built snapshot above, via `process.exec`) before configuring auth and mounting as shown above. Slower cold start per sandbox, no snapshot to maintain.

### Production: scoped ephemeral keys

For non-test workloads, Mesa recommends minting a short-lived, scoped API key per sandbox session rather than passing a long-lived `MESA_API_KEY` into the sandbox. Use the [Mesa SDK](https://docs.mesa.dev) on a trusted host to derive an ephemeral key from the long-lived one — the long-lived key never leaves the host process. Mesa SDKs are available for TypeScript, Python, and Rust; for other languages, use the [Mesa REST API](https://docs.mesa.dev/content/api-reference/overview) directly.

```python
import asyncio
import os
from daytona import CreateSandboxFromSnapshotParams, Daytona
from mesa_sdk import Mesa


async def mint_ephemeral_key() -> str:
    async with Mesa(api_key=os.environ["MESA_API_KEY"], org=os.environ["MESA_ORG"]) as mesa:
        key = await mesa.api_keys.create(
            name="sandbox-session",
            scopes=["read", "write"],
            expires_in_seconds=3600,
        )
        return key.key


ephemeral_key = asyncio.run(mint_ephemeral_key())

daytona = Daytona()
sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="fuse-mesa",
        env_vars={
            "MESA_API_KEY": ephemeral_key,
            "MESA_ORG": os.environ["MESA_ORG"],
        },
    )
)
```

```typescript
import { Daytona } from '@daytona/sdk'
import { Mesa } from '@mesadev/sdk'

const mesa = new Mesa({ apiKey: process.env.MESA_API_KEY!, org: process.env.MESA_ORG! })

const ephemeralKey = await mesa.apiKeys.create({
  name: 'sandbox-session',
  scopes: ['read', 'write'],
  expires_in_seconds: 3600,
})

const daytona = new Daytona()
const sandbox = await daytona.create({
  snapshot: 'fuse-mesa',
  envVars: {
    MESA_API_KEY: ephemeralKey.key,
    MESA_ORG: process.env.MESA_ORG!,
  },
})
```

The rest of the launch flow (writing the TOML config, `mesa auth set-key`, `mesa mount --daemonize`) is unchanged — the sandbox does not know whether the key it received is long-lived or ephemeral.

For repo-scoped or path-scoped keys, see the Mesa [auth and permissions guide](https://docs.mesa.dev/content/getting-started/auth-and-permissions). For the full integration recipe, see the Mesa [Daytona guide](https://docs.mesa.dev/content/integration-guides/daytona).

## Unmount

When a sandbox is deleted via `daytona.delete(sandbox)`, the container teardown automatically removes any active FUSE mounts and shuts down their daemons. For normal cleanup, this is all that is needed — no manual unmount required.

To free a mount path during a sandbox lifetime (for example, to remount with different credentials or before persisting a workspace archive), relocate the mount onto a throwaway path:

```bash
sudo mkdir -p /tmp/.fuse-defunct-$$
sudo mount --move <your-mount-path> /tmp/.fuse-defunct-$$
```

After this, the original mount path is free for remounting. The FUSE daemon stays alive serving the mount at the new path; both the relocated mount and the daemon are cleaned up automatically when the sandbox is deleted.

This works for any FUSE-based mount — verified against `mount-s3`, `gcsfuse`, and `blobfuse2`.
