# Accessibility operations

Use Linux accessibility operations to inspect the AT-SPI tree and interact with UI elements by node ID. Start Computer Use before calling accessibility methods.

:::note[App accessibility support]
Accessibility operations read the semantic UI information that applications expose over AT-SPI. Apps or custom widgets that do not expose accessibility objects may return sparse nodes, generic roles, or no actionable nodes; mouse, keyboard, and screenshot operations remain available for those cases.
:::

## Get tree

Read an accessibility tree for the focused app, a specific process, or all apps.


```python
# Focused app
focused_tree = sandbox.computer_use.accessibility.get_tree(scope="focused", max_depth=2)

# Specific process
process_tree = sandbox.computer_use.accessibility.get_tree(
    scope="pid",
    pid=1234,
    max_depth=2,
)

# All apps
desktop_tree = sandbox.computer_use.accessibility.get_tree(scope="all", max_depth=2)
```


```typescript
// Focused app
const focusedTree = await sandbox.computerUse.accessibility.getTree({
  scope: 'focused',
  maxDepth: 2,
});

// Specific process
const processTree = await sandbox.computerUse.accessibility.getTree({
  scope: 'pid',
  pid: 1234,
  maxDepth: 2,
});

// All apps
const desktopTree = await sandbox.computerUse.accessibility.getTree({
  scope: 'all',
  maxDepth: 2,
});
```


```ruby
# Focused app
focused_tree = sandbox.computer_use.accessibility.get_tree(scope: "focused", max_depth: 2)

# Specific process
process_tree = sandbox.computer_use.accessibility.get_tree(
  scope: "pid",
  pid: 1234,
  max_depth: 2
)

# All apps
desktop_tree = sandbox.computer_use.accessibility.get_tree(scope: "all", max_depth: 2)
```


```go
maxDepth := 2

// Focused app
focusedScope := "focused"
focusedTree, err := sandbox.ComputerUse.Accessibility().GetTree(ctx, &daytona.AccessibilityTreeOptions{
	Scope:    &focusedScope,
	MaxDepth: &maxDepth,
})
if err != nil {
	log.Fatal(err)
}

// Specific process
processScope := "pid"
pid := 1234
processTree, err := sandbox.ComputerUse.Accessibility().GetTree(ctx, &daytona.AccessibilityTreeOptions{
	Scope:    &processScope,
	PID:      &pid,
	MaxDepth: &maxDepth,
})
if err != nil {
	log.Fatal(err)
}

// All apps
allScope := "all"
desktopTree, err := sandbox.ComputerUse.Accessibility().GetTree(ctx, &daytona.AccessibilityTreeOptions{
	Scope:    &allScope,
	MaxDepth: &maxDepth,
})
if err != nil {
	log.Fatal(err)
}
```


```java
// Focused app
var focusedTree = sandbox.computerUse.getAccessibilityTree("focused", null, 2);

// Specific process
var processTree = sandbox.computerUse.getAccessibilityTree("pid", 1234, 2);

// All apps
var desktopTree = sandbox.computerUse.getAccessibilityTree("all", null, 2);
```


```bash
# Focused app
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/tree?scope=focused&maxDepth=2'

# Specific process
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/tree?scope=pid&pid=1234&maxDepth=2'

# All apps
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/tree?scope=all&maxDepth=2'
```


## Find nodes

Search the accessibility tree by role, accessible name, state, and scope.


```python
# Find buttons by accessible name
buttons = sandbox.computer_use.accessibility.find_nodes(
    scope="focused",
    role="button",
    name="Submit",
    name_match="substring",
    limit=10,
)

# Find text entries in a process
entries = sandbox.computer_use.accessibility.find_nodes(
    scope="pid",
    pid=1234,
    role="entry",
    states=["enabled", "focusable"],
    limit=10,
)

# Find visible nodes across all apps
visible_nodes = sandbox.computer_use.accessibility.find_nodes(
    scope="all",
    states=["visible"],
    limit=20,
)
```


```typescript
// Find buttons by accessible name
const buttons = await sandbox.computerUse.accessibility.findNodes({
  scope: 'focused',
  role: 'button',
  name: 'Submit',
  nameMatch: 'substring',
  limit: 10,
});

// Find text entries in a process
const entries = await sandbox.computerUse.accessibility.findNodes({
  scope: 'pid',
  pid: 1234,
  role: 'entry',
  states: ['enabled', 'focusable'],
  limit: 10,
});

// Find visible nodes across all apps
const visibleNodes = await sandbox.computerUse.accessibility.findNodes({
  scope: 'all',
  states: ['visible'],
  limit: 20,
});
```


```ruby
# Find buttons by accessible name
buttons = sandbox.computer_use.accessibility.find_nodes(
  scope: "focused",
  role: "button",
  name: "Submit",
  name_match: "substring",
  limit: 10
)

# Find text entries in a process
entries = sandbox.computer_use.accessibility.find_nodes(
  scope: "pid",
  pid: 1234,
  role: "entry",
  states: ["enabled", "focusable"],
  limit: 10
)

# Find visible nodes across all apps
visible_nodes = sandbox.computer_use.accessibility.find_nodes(
  scope: "all",
  states: ["visible"],
  limit: 20
)
```


```go
limit := 10

// Find buttons by accessible name
focusedScope := "focused"
buttonRole := "button"
submitName := "Submit"
substringMatch := "substring"
buttons, err := sandbox.ComputerUse.Accessibility().FindNodes(ctx, &daytona.AccessibilityFindOptions{
	Scope:     &focusedScope,
	Role:      &buttonRole,
	Name:      &submitName,
	NameMatch: &substringMatch,
	Limit:     &limit,
})
if err != nil {
	log.Fatal(err)
}

// Find text entries in a process
processScope := "pid"
pid := 1234
entryRole := "entry"
entries, err := sandbox.ComputerUse.Accessibility().FindNodes(ctx, &daytona.AccessibilityFindOptions{
	Scope:  &processScope,
	PID:    &pid,
	Role:   &entryRole,
	States: []string{"enabled", "focusable"},
	Limit:  &limit,
})
if err != nil {
	log.Fatal(err)
}

// Find visible nodes across all apps
allScope := "all"
visibleLimit := 20
visibleNodes, err := sandbox.ComputerUse.Accessibility().FindNodes(ctx, &daytona.AccessibilityFindOptions{
	Scope:  &allScope,
	States: []string{"visible"},
	Limit:  &visibleLimit,
})
if err != nil {
	log.Fatal(err)
}
```


```java
// Find buttons by accessible name
var buttons = sandbox.computerUse.findAccessibilityNodes(
    new FindAccessibilityNodesRequest()
        .scope("focused")
        .role("button")
        .name("Submit")
        .nameMatch("substring")
        .limit(10)
);

// Find text entries in a process
var entries = sandbox.computerUse.findAccessibilityNodes(
    new FindAccessibilityNodesRequest()
        .scope("pid")
        .pid(1234)
        .role("entry")
        .states(java.util.List.of("enabled", "focusable"))
        .limit(10)
);

// Find visible nodes across all apps
var visibleNodes = sandbox.computerUse.findAccessibilityNodes(
    new FindAccessibilityNodesRequest()
        .scope("all")
        .states(java.util.List.of("visible"))
        .limit(20)
);
```


```bash
# Find buttons by accessible name
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/find' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{
  "scope": "focused",
  "role": "button",
  "name": "Submit",
  "nameMatch": "substring",
  "limit": 10
}'

# Find text entries in a process
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/find' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{
  "scope": "pid",
  "pid": 1234,
  "role": "entry",
  "states": ["enabled", "focusable"],
  "limit": 10
}'

# Find visible nodes across all apps
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/find' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{
  "scope": "all",
  "states": ["visible"],
  "limit": 20
}'
```


## Focus node

Move keyboard focus to a node returned by `get_tree` or `find_nodes`.


```python
sandbox.computer_use.accessibility.focus_node("node-id")
```


```typescript
await sandbox.computerUse.accessibility.focusNode('node-id');
```


```ruby
sandbox.computer_use.accessibility.focus_node(id: "node-id")
```


```go
if err := sandbox.ComputerUse.Accessibility().FocusNode(ctx, "node-id"); err != nil {
	log.Fatal(err)
}
```


```java
sandbox.computerUse.focusAccessibilityNode("node-id");
```


```bash
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/node/focus' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"id":"node-id"}'
```


## Invoke node

Run a node action, such as pressing a button.


```python
# Invoke the primary action
sandbox.computer_use.accessibility.invoke_node("node-id")

# Invoke a named action
sandbox.computer_use.accessibility.invoke_node("node-id", action="click")
```


```typescript
// Invoke the primary action
await sandbox.computerUse.accessibility.invokeNode('node-id');

// Invoke a named action
await sandbox.computerUse.accessibility.invokeNode('node-id', 'click');
```


```ruby
# Invoke the primary action
sandbox.computer_use.accessibility.invoke_node(id: "node-id")

# Invoke a named action
sandbox.computer_use.accessibility.invoke_node(id: "node-id", action: "click")
```


```go
// Invoke the primary action
if err := sandbox.ComputerUse.Accessibility().InvokeNode(ctx, "node-id", nil); err != nil {
	log.Fatal(err)
}

// Invoke a named action
action := "click"
if err := sandbox.ComputerUse.Accessibility().InvokeNode(ctx, "node-id", &action); err != nil {
	log.Fatal(err)
}
```


```java
// Invoke the primary action
sandbox.computerUse.invokeAccessibilityNode("node-id");

// Invoke a named action
sandbox.computerUse.invokeAccessibilityNode("node-id", "click");
```


```bash
# Invoke the primary action
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/node/invoke' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"id":"node-id"}'

# Invoke a named action
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/node/invoke' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"id":"node-id","action":"click"}'
```


## Set node value

Write text or value content to nodes that support value changes.


```python
sandbox.computer_use.accessibility.set_node_value("node-id", "hello")
```


```typescript
await sandbox.computerUse.accessibility.setNodeValue('node-id', 'hello');
```


```ruby
sandbox.computer_use.accessibility.set_node_value(id: "node-id", value: "hello")
```


```go
if err := sandbox.ComputerUse.Accessibility().SetNodeValue(ctx, "node-id", "hello"); err != nil {
	log.Fatal(err)
}
```


```java
sandbox.computerUse.setAccessibilityNodeValue("node-id", "hello");
```


```bash
curl 'https://proxy.app.daytona.io/toolbox/{sandboxId}/computeruse/a11y/node/value' \
  --request POST \
  --header 'Content-Type: application/json' \
  --data '{"id":"node-id","value":"hello"}'
```

---

# Snapshots

Snapshots are persistent, point-in-time captures of sandbox state, including the filesystem, installed packages, dependencies, and settings. A snapshot saves a sandbox's state so you can restore it later, and any number of new sandboxes can start from the same snapshot.

Daytona provides default snapshots for creating sandboxes. You can also create snapshots from images, capture the state of existing sandboxes, or create warm pools for a snapshot:

- **Create snapshots from an image**: define the base operating system, language runtimes, packages, and project-level setup in an image or Dockerfile, and Daytona builds it into a snapshot you can use to create sandboxes
- **Create snapshots from a sandbox**: captures and persists a sandbox's current state; container sandboxes capture filesystem state only (**cold snapshots**), VM sandboxes capture filesystem and memory state (**hot snapshots**)
- **Warm pools**: keep a configured number of pre-created, running sandboxes built from a snapshot; matching sandbox create requests claim one warm sandbox from the pool instantly instead of provisioning a new sandbox

## Default snapshots

| **Snapshot**            | **vCPU** | **Memory** | **Storage** | **GPU** | **Sandbox Class** |
| ----------------------- | -------- | ---------- | ----------- | ------- | ----------------- |
| **`daytona-small`**     | 1        | 1GiB       | 3GiB        |         | Container         |
| **`daytona-medium`**    | 2        | 4GiB       | 8GiB        |         | Container         |
| **`daytona-large`**     | 4        | 8GiB       | 10GiB       |         | Container         |
| **`daytona-gpu`**       | 1        | 1GiB       | 1GiB        | 1       | GPU               |
| **`daytona-vm-small`**  | 1        | 1GiB       | 3GiB        |         | Linux VM          |
| **`daytona-vm-medium`** | 2        | 4GiB       | 8GiB        |         | Linux VM          |
| **`daytona-vm-large`**  | 4        | 8GiB       | 10GiB       |         | Linux VM          |
| **`windows-small`**     | 1        | 4GiB       | 30GiB       |         | Windows           |
| **`windows-medium`**    | 2        | 8GiB       | 50GiB       |         | Windows           |
| **`windows-large`**     | 4        | 16GiB      | 50GiB       |         | Windows           |

1. Go to Daytona Sandboxes (app.daytona.io/dashboard/sandboxes)
2. Click Create Sandbox
3. Select a **`snapshot`**
4. Click Create


```python
from daytona import Daytona, CreateSandboxFromSnapshotParams

daytona = Daytona()
sandbox = daytona.create(
    CreateSandboxFromSnapshotParams(
        snapshot="daytona-small",
    )
)
```


```typescript
import { Daytona } from '@daytona/sdk'

const daytona = new Daytona()
const sandbox = await daytona.create({
  snapshot: 'daytona-small',
})
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new
sandbox = daytona.create(
  Daytona::CreateSandboxFromSnapshotParams.new(
    snapshot: 'daytona-small'
  )
)
```


```go
package main

import (
	"context"
	"github.com/daytona/clients/sdk-go/pkg/daytona"
	"github.com/daytona/clients/sdk-go/pkg/types"
)

func main() {
	client, _ := daytona.NewClient()
	ctx := context.Background()
	params := types.SnapshotParams{
		Snapshot: "daytona-small",
	}
	_, _ = client.Create(ctx, params)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setSnapshot("daytona-small");
            Sandbox sandbox = daytona.create(params);
        }
    }
}
```


```bash
daytona create --snapshot daytona-small
```


```bash
curl 'https://app.daytona.io/api/sandbox' \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_API_KEY' \
  --data '{
  "snapshot": "daytona-small"
}'
```


Default snapshots include pre-installed Python and Node.js packages.

<details><summary>Python (pip)</summary>

| **Package**            | **Version** |
| ---------------------- | ----------- |
| **`anthropic`**        | v0.120.2     |
| **`beautifulsoup4`**   | v4.14.3     |
| **`claude-agent-sdk`** | v0.2.130     |
| **`openai-agents`**    | v0.19.4     |
| **`daytona`**          | v0.203.0    |
| **`django`**           | v6.0.1      |
| **`flask`**            | v3.1.2      |
| **`huggingface-hub`**  | v0.36.0     |
| **`instructor`**       | v1.14.4     |
| **`keras`**            | v3.13.0     |
| **`langchain`**        | v1.2.7      |
| **`llama-index`**      | v0.14.13    |
| **`matplotlib`**       | v3.10.8     |
| **`numpy`**            | v2.4.1      |
| **`ollama`**           | v0.6.1      |
| **`openai`**           | v2.53.0     |
| **`opencv-python`**    | v4.13.0.90  |
| **`pandas`**           | v2.3.3      |
| **`pillow`**           | v12.1.0     |
| **`pipx`**             | v1.8.0      |
| **`pydantic-ai`**      | v1.47.0     |
| **`python-lsp-server`**    | v1.14.0     |
| **`requests`**         | v2.32.5     |
| **`scikit-learn`**     | v1.8.0      |
| **`scipy`**            | v1.17.0     |
| **`seaborn`**          | v0.13.2     |
| **`sqlalchemy`**       | v2.0.46     |
| **`torch`**            | v2.10.0     |
| **`transformers`**     | v4.57.6     |
| **`uv`**               | v0.9.26     |

</details>

<details><summary>Node.js (npm)</summary>

| **Package**                      | **Version** |
| -------------------------------- | ----------- |
| **`@anthropic-ai/claude-code`**  | v2.1.220     |
| **`@openai/codex`**              | v0.146.0    |
| **`bun`**                        | v1.3.6      |
| **`openclaw`**                   | v2026.7.1-2   |
| **`opencode-ai`**                | v1.18.14     |
| **`ts-node`**                    | v10.9.2     |
| **`typescript`**                 | v5.9.3      |
| **`typescript-language-server`** | v5.1.3      |

</details>

## Create snapshots

Create a snapshot.

1. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
2. Click Create Snapshot
3. Enter the snapshot **`name`** and **`image`** of any publicly accessible image or container registry
    - **Snapshot name**: identifier used to reference the snapshot
    - **Snapshot image**: base image for the snapshot, must include either a tag or a digest (e.g., **`ubuntu:22.04`**); the **`latest`**/**`lts`**/**`stable`** tags are not supported
4. Click Create


```python
from daytona import Daytona, CreateSnapshotParams

daytona = Daytona()
snapshot = daytona.snapshot.create(
    CreateSnapshotParams(name="my-awesome-snapshot", image="ubuntu:22.04"),
)
```


```typescript
import { Daytona } from "@daytona/sdk";

const daytona = new Daytona();
const snapshot = await daytona.snapshot.create({
  name: "my-awesome-snapshot",
  image: "python:3.12",
});
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new
snapshot = daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(name: 'my-awesome-snapshot', image: 'python:3.12')
)
```


```go
package main

import (
	"context"

	"github.com/daytona/clients/sdk-go/pkg/daytona"
	"github.com/daytona/clients/sdk-go/pkg/types"
)

func main() {
	client, _ := daytona.NewClient()
	ctx := context.Background()
	snapshot, logCh, _ := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
		Name:  "my-awesome-snapshot",
		Image: "python:3.12",
	})
	for range logCh {
	}
	_ = snapshot
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.model.Snapshot;

final class CreateSnapshot {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Snapshot snapshot = daytona.snapshot().create("my-awesome-snapshot", "python:3.12");
        }
    }
}
```


```bash
daytona snapshot create my-awesome-snapshot --image python:3.11-slim --cpu 2 --memory 4
```


```bash
curl https://app.daytona.io/api/snapshots \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN' \
  --data '{
    "name": "my-awesome-snapshot",
    "imageName": "python:3.11-slim",
    "cpu": 2,
    "memory": 4
  }'
```


## VM snapshots

Daytona provides methods to create VM snapshots for **Linux VM** and **Windows**.

VM snapshots are used to create VM sandboxes. VM snapshots are distinct from container snapshots and cannot be used to create container sandboxes. VM snapshots support VM-only capabilities such as creating a snapshot from a sandbox.

Create a Linux VM snapshot.

:::note
Linux VM snapshots must be created from an existing image reference. Dockerfile and declarative image builds are not supported for the Linux VM sandbox class and fail during the build step. To use a custom image, push it to a public or private registry and create the snapshot from that image, or create a snapshot from a sandbox.
:::

1. Create a snapshot from an **`image`**
2. Set the snapshot's sandbox class to **`LINUX_VM`**


```python
from daytona import Daytona, CreateSnapshotParams, SandboxClass

daytona = Daytona()
snapshot = daytona.snapshot.create(
    CreateSnapshotParams(
        name="my-vm-snapshot",
        image="ubuntu:22.04",
        sandbox_class=SandboxClass.LINUX_VM,
    )
)
```


```typescript
import { Daytona, SandboxClass } from "@daytona/sdk";

const daytona = new Daytona();
const snapshot = await daytona.snapshot.create({
  name: "my-vm-snapshot",
  image: "ubuntu:22.04",
  sandboxClass: SandboxClass.LINUX_VM,
});
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new
snapshot = daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(
    name: 'my-vm-snapshot',
    image: 'ubuntu:22.04',
    sandbox_class: DaytonaApiClient::SandboxClass::LINUX_VM
  )
)
```


```go
package main

import (
	"context"

	"github.com/daytona/clients/sdk-go/pkg/daytona"
	"github.com/daytona/clients/sdk-go/pkg/types"
)

func main() {
	client, _ := daytona.NewClient()
	ctx := context.Background()

	sandboxClass := types.SandboxClassLinuxVM
	snapshot, logCh, _ := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
		Name:         "my-vm-snapshot",
		Image:        "ubuntu:22.04",
		SandboxClass: &sandboxClass,
	})
	for range logCh {
	}
	_ = snapshot
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.api.client.model.SandboxClass;
import io.daytona.sdk.model.Snapshot;

final class CreateVmSnapshot {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Snapshot snapshot = daytona.snapshot().create("my-vm-snapshot", "ubuntu:22.04", SandboxClass.LINUX_VM);
        }
    }
}
```


```bash
daytona snapshot create my-vm-snapshot --image ubuntu:22.04 --sandbox-class linux-vm
```


```bash
curl https://app.daytona.io/api/snapshots \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN' \
  --data '{
    "name": "my-vm-snapshot",
    "imageName": "ubuntu:22.04",
    "sandboxClass": "linux-vm"
  }'
```

Windows snapshots are used to create Windows sandboxes. They cannot be created from a base image. They are produced only through the snapshot-from-sandbox flow by starting from an existing Windows sandbox and capturing its current state as a snapshot.

## GPU snapshots

Create a GPU snapshot. GPU snapshots are used to create GPU sandboxes.

1. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
2. Click Create Snapshot
3. Enter the snapshot **`name`** and **`image`**
4. Select the **`Allocate GPU`** checkbox
5. Specify the **`GPU type`**(s):

    - **`NVIDIA H100`**
    - **`NVIDIA H200`**
    - **`NVIDIA RTX PRO 6000`**
    - **`NVIDIA RTX 4090`**
    - **`NVIDIA RTX 5090`**

6. Click Create


```python
from daytona import CreateSnapshotParams, Daytona, Image, Resources

daytona = Daytona()
snapshot = daytona.snapshot.create(
    CreateSnapshotParams(
        name="my-gpu-snapshot",
        image=Image.base("python:3.12"),
        resources=Resources(cpu=1, memory=1, disk=1, gpu=1),
    ),
)
```


```typescript
import { Daytona } from "@daytona/sdk";

const daytona = new Daytona();
const snapshot = await daytona.snapshot.create({
  name: "my-gpu-snapshot",
  image: "python:3.12",
  resources: { cpu: 1, memory: 1, disk: 1, gpu: 1 },
});
```


```ruby
require 'daytona'

daytona = Daytona::Daytona.new
snapshot = daytona.snapshot.create(
  Daytona::CreateSnapshotParams.new(
    name: 'my-gpu-snapshot',
    image: 'python:3.12',
    resources: Daytona::Resources.new(cpu: 1, memory: 1, disk: 1, gpu: 1)
  )
)
```


```go
package main

import (
	"context"
	"github.com/daytona/clients/sdk-go/pkg/daytona"
	"github.com/daytona/clients/sdk-go/pkg/types"
)

func main() {
	client, _ := daytona.NewClient()
	ctx := context.Background()
	snapshot, logCh, _ := client.Snapshot.Create(ctx, &types.CreateSnapshotParams{
		Name:  "my-gpu-snapshot",
		Image: "python:3.12",
		Resources: &types.Resources{
			CPU: 1,
			Memory: 1,
			Disk: 1,
			GPU: 1,
		},
	})
	for range logCh {
	}
	_ = snapshot
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Image;
import io.daytona.sdk.model.Resources;
import io.daytona.sdk.model.Snapshot;

final class CreateGpuSnapshot {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            Resources resources = new Resources();
            resources.setCpu(1);
            resources.setMemory(1);
            resources.setDisk(1);
            resources.setGpu(1);
            Snapshot snapshot = daytona.snapshot().create(
                "my-gpu-snapshot",
                Image.base("python:3.12"),
                resources,
                null
            );
        }
    }
}
```


```bash
curl https://app.daytona.io/api/snapshots \
  --request POST \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN' \
  --data '{
    "name": "my-gpu-snapshot",
    "imageName": "python:3.12",
    "cpu": 1,
    "memory": 1,
    "disk": 1,
    "gpu": 1
  }'
```


## Create snapshot from sandbox

Create a snapshot from a running or stopped sandbox.

Container sandboxes capture filesystem state only (**cold snapshot**):

| **Snapshot type** | **Include memory**    | **Snapshot contents** | **Required sandbox state** |
| ----------------- | --------------------- | --------------------- | -------------------------- |
| Cold              | **`false`** (default) | Filesystem only       | Stopped                    |


```python
sandbox._experimental_create_snapshot("my-snapshot")
```


```typescript
await sandbox._experimental_createSnapshot('my-snapshot')
```


```ruby
sandbox.experimental_create_snapshot(name: 'my-snapshot')
```


```go
err := sandbox.ExperimentalCreateSnapshot(ctx, "my-snapshot")
if err != nil {
    return err
}
```


```java
sandbox.experimentalCreateSnapshot("my-snapshot");
```


```bash
curl 'https://app.daytona.io/api/sandbox/{sandboxIdOrName}/snapshot' \
  --request POST \
  --header 'X-Daytona-Organization-ID: YOUR_ORGANIZATION_ID' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_API_KEY' \
  --data '{
  "name": "my-snapshot",
  "includeMemory": false
}'
```

Linux VM sandboxes capture filesystem state only (**cold snapshot**) or filesystem and memory state (**hot snapshot**) through the `includeMemory` parameter:

| **Snapshot type** | **Include memory**    | **Snapshot contents** | **Required sandbox state** |
| ----------------- | --------------------- | --------------------- | -------------------------- |
| Cold              | **`false`** (default) | Filesystem only       | Stopped                    |
| Hot               | **`true`**            | Filesystem and memory | Started                    |


```python
# Cold snapshot (filesystem only, sandbox stopped)
sandbox._experimental_create_snapshot("my-snapshot")

# Hot snapshot (filesystem and memory, sandbox running)
sandbox._experimental_create_snapshot("my-vm-snapshot", include_memory=True)
```


```typescript
// Cold snapshot (filesystem only, sandbox stopped)
await sandbox._experimental_createSnapshot('my-snapshot')

// Hot snapshot (filesystem and memory, sandbox running)
await sandbox._experimental_createSnapshot('my-vm-snapshot', 60, true)
```


```ruby
# Cold snapshot (filesystem only, sandbox stopped)
sandbox.experimental_create_snapshot(name: 'my-snapshot')

# Hot snapshot (filesystem and memory, sandbox running)
sandbox.experimental_create_snapshot(name: 'my-vm-snapshot', include_memory: true)
```


```go
// Cold snapshot (filesystem only, sandbox stopped)
err := sandbox.ExperimentalCreateSnapshot(ctx, "my-snapshot")
if err != nil {
    return err
}

// Hot snapshot (filesystem and memory, sandbox running)
err = sandbox.ExperimentalCreateSnapshotWithMemory(ctx, "my-vm-snapshot", 60*time.Second)
if err != nil {
    return err
}
```


```java
// Cold snapshot (filesystem only, sandbox stopped)
sandbox.experimentalCreateSnapshot("my-snapshot");

// Hot snapshot (filesystem and memory, sandbox running)
sandbox.experimentalCreateSnapshot("my-vm-snapshot", 60, true);
```


```bash
# Cold snapshot (filesystem only, sandbox stopped)
curl 'https://app.daytona.io/api/sandbox/{sandboxIdOrName}/snapshot' \
  --request POST \
  --header 'X-Daytona-Organization-ID: YOUR_ORGANIZATION_ID' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_API_KEY' \
  --data '{
  "name": "my-snapshot",
  "includeMemory": false
}'

# Hot snapshot (filesystem and memory, sandbox running)
curl 'https://app.daytona.io/api/sandbox/{sandboxIdOrName}/snapshot' \
  --request POST \
  --header 'X-Daytona-Organization-ID: YOUR_ORGANIZATION_ID' \
  --header 'Content-Type: application/json' \
  --header 'Authorization: Bearer YOUR_API_KEY' \
  --data '{
  "name": "my-vm-snapshot",
  "includeMemory": true
}'
```

Windows sandboxes capture filesystem state only (**cold snapshot**) or filesystem and memory state (**hot snapshot**) through the `includeMemory` parameter:

| **Snapshot type** | **Include memory**    | **Snapshot contents** | **Required sandbox state** |
| ----------------- | --------------------- | --------------------- | -------------------------- |
| Cold              | **`false`** (default) | Filesystem only       | Stopped                    |
| Hot               | **`true`**            | Filesystem and memory | Started                    |

(Same cold/hot snapshot commands as Linux VM above, using `"my-vm-snapshot"` on a Windows sandbox.)

## Snapshots from private registries

Create a snapshot from images from private container registries.

1. Go to Daytona Registries (app.daytona.io/dashboard/registries)
2. Click Add Registry and select your provider:

    - Docker Hub
    - Google Artifact Registry
    - GitHub Container Registry
    - Amazon ECR

3. Enter the required fields
4. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
5. Click Create Snapshot
6. Enter the snapshot **`name`** and the full **`image`** reference, including the registry host and repository (e.g. **`my-registry.com/<repo>/custom-alpine:3.21`**)

#### Docker Hub

Create a snapshot from Docker Hub images.

1. Go to Daytona Registries (app.daytona.io/dashboard/registries)
2. Click Add Registry and select the **Docker Hub** tab
3. Input the following fields:
   - **Username**: your Docker Hub username (the account with access to the image)
   - **Personal Access Token**: a Docker Hub PAT; not your account password
   - **Registry URL**: auto-filled with **`docker.io`** and not shown in the form
4. Create the snapshot using the full image reference

    **`docker.io/<username>/<image>:<tag>`**

#### Google Artifact Registry

Create a snapshot from images from Google Artifact Registry.

1. Go to Daytona Registries (app.daytona.io/dashboard/registries)
2. Click Add Registry and select the **Google** tab
3. Input the following fields:
   - **Registry URL**: the base URL for your region

      **`https://<region>-docker.pkg.dev`**
   - **Service Account JSON Key**: the contents of your service account key JSON file
   - **Google Cloud Project ID**: your GCP project ID
   - **Username**: auto-filled with **`_json_key`** (required by Google for service-account auth)
4. Create the snapshot using the full image reference

    **`<region>-docker.pkg.dev/<project>/<repo>/<image>:<tag>`**

#### GitHub Container Registry

Create a snapshot from images from GitHub Container Registry.

1. Go to Daytona Registries (app.daytona.io/dashboard/registries)
2. Click Add Registry and select the **GitHub** tab
3. Input the following fields:
   - **GitHub Username**: the account with access to the image
   - **Personal Access Token**: a GitHub PAT with **`read:packages`** scope (and **`write:packages`** / **`delete:packages`** for pushing or deleting)
   - **Registry URL**: auto-filled with **`ghcr.io`** and not shown in the form
3. Create the snapshot using the full image reference

    **`ghcr.io/<owner>/<image>:<tag>`**

#### Amazon ECR

Create a snapshot from images from Amazon Elastic Container Registry.

Daytona pulls private ECR images via cross-account IAM role assumption. You create a role in your AWS account that trusts Daytona's broker principal, and Daytona assumes it on every pull to fetch a short-lived ECR token.

- **Daytona Broker ARN**

    The IAM principal Daytona uses to assume into your role. Self-hosted: substitute the IAM role your API pods assume (e.g. via IRSA).

    `arn:aws:iam::967657494466:role/DaytonaEcrCredentialBroker`
- **External ID**

    Your Daytona organization ID, visible in the dashboard URL (`/dashboard/<orgId>/...`) and on your organization settings page.

1. Create an IAM role in your AWS account

    - **Trust policy**

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": { "AWS": "arn:aws:iam::967657494466:role/DaytonaEcrCredentialBroker" },
        "Action": "sts:AssumeRole",
        "Condition": {
          "StringEquals": {
            "sts:ExternalId": "<YOUR_EXTERNAL_ID>"
          }
        }
      }]
    }
    ```

    - **Permissions policy (read-only on ECR)**

    ```json
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ],
        "Resource": "*"
      }]
    }
    ```

2. Go to Daytona Registries (app.daytona.io/dashboard/registries)
3. Click Add Registry and select the **Amazon ECR** tab
4. Input the following fields:
   - **Registry URL**: **`<account_id>.dkr.ecr.<region>.amazonaws.com`**
   - **Role ARN**: the role you created in step 1

   Password is not used for ECR. Daytona resolves credentials server-side by assuming the role you created in step 1, using your organization ID as the **`AssumeRole ExternalId`**.
5. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
6. Click Create Snapshot
7. Enter the snapshot **`name`** and the full **`image`** reference

    **`<account_id>.dkr.ecr.<region>.amazonaws.com/<repo>/<image>:<tag>`**
8. (Optional) Harden the trust policy

    Daytona sends a `daytona-<orgId>-pull` session name on every AssumeRole call. You can require it in your trust policy for CloudTrail audit visibility. Add inside `Condition`:

    ```json
    "StringLike": {
      "sts:RoleSessionName": "daytona-<YOUR_EXTERNAL_ID>-*"
    }
    ```

## Snapshots from local images

Create a snapshot from local images or from local Dockerfiles.

Daytona expects the local image to be built for AMD64 architecture. Therefore, the `--platform=linux/amd64` flag is required when building the Docker image if your machine is running on a different architecture.

1. Ensure the image and tag you want to use is available

```bash
docker images
```

2. Create a snapshot and push it to Daytona:

```bash
daytona snapshot push custom-alpine:3.21 --name alpine-minimal
```

Alternatively, use the `--dockerfile` flag under `create` to pass the path to the Dockerfile you want to use and Daytona will build the snapshot for you. The `COPY`/`ADD` commands will be automatically parsed and added to the context. To manually add files to the context, use the `--context` flag.

```bash
daytona snapshot create my-awesome-snapshot --dockerfile ./Dockerfile
```

:::note
Dockerfile builds are not supported for VM snapshots. For Linux VM snapshots, push the built image to a registry and create the snapshot from the image reference.
:::

## Get snapshot

Get a snapshot by name.


```python
daytona.snapshot.get("my-awesome-snapshot")
```


```typescript
await daytona.snapshot.get('my-awesome-snapshot')
```


```ruby
daytona.snapshot.get('my-awesome-snapshot')
```


```go
_, err := client.Snapshots.Get(ctx, "my-awesome-snapshot")
```


```java
daytona.snapshot().get("my-awesome-snapshot");
```


```bash
curl https://app.daytona.io/api/snapshots/my-awesome-snapshot \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN'
```


## List snapshots

List snapshots and view their details.


```python
daytona.snapshot.list(page=2, limit=10)
```


```typescript
await daytona.snapshot.list(2, 10)
```


```ruby
daytona.snapshot.list(page: 2, limit: 10)
```


```go
page, limit := 2, 10
_, err := client.Snapshots.List(ctx, &page, &limit)
```


```java
daytona.snapshot().list(2, 10);
```


```bash
# List snapshots with pagination
daytona snapshot list --page 2 --limit 10
```


```bash
curl 'https://app.daytona.io/api/snapshots?page=2&limit=10' \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN'
```


## Activate snapshots

Activate an inactive snapshot.

Snapshots automatically become inactive after 2 weeks of not being used.

1. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
2. Click the three dots at the end of the row for the snapshot you want to activate
3. Click Activate

```python
daytona.snapshot.activate("my-awesome-snapshot")
```
```typescript
await daytona.snapshot.activate("my-awesome-snapshot")
```
```ruby
daytona.snapshot.activate('my-awesome-snapshot')
```

```bash
curl https://app.daytona.io/api/snapshots/my-inactive-snapshot/activate \
  --request POST \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN'
```


## Deactivate snapshots

Deactivate a snapshot.

Deactivated snapshots are not available for new sandboxes. Deactivating a snapshot also pauses top-ups of its warm pools; the pool reports the reason in its `errorReason` field.

1. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
2. Click the three dots at the end of the row for the snapshot you want to deactivate
3. Click Deactivate

## Delete snapshots

Delete a snapshot.

Deleted snapshots cannot be recovered. Deleting a snapshot also deletes its warm pools and destroys their unclaimed warm sandboxes.

1. Go to Daytona Snapshots (app.daytona.io/dashboard/snapshots)
2. Click the three dots at the end of the row for the snapshot you want to delete
3. Click Delete


```python
daytona.snapshot.delete(daytona.snapshot.get("my-awesome-snapshot"))
```


```typescript
await daytona.snapshot.delete(await daytona.snapshot.get("my-awesome-snapshot"))
```


```ruby
daytona.snapshot.delete(daytona.snapshot.get('my-awesome-snapshot'))
```


```go
snapshot, err := client.Snapshots.Get(ctx, "my-awesome-snapshot")
err = client.Snapshots.Delete(ctx, snapshot)
```


```java
daytona.snapshot().delete(daytona.snapshot().get("my-awesome-snapshot").getId());
```


```bash
daytona snapshot delete my-awesome-snapshot
```


```bash
curl https://app.daytona.io/api/snapshots/my-awesome-snapshot \
  --request DELETE \
  --header 'Authorization: Bearer YOUR_SECRET_TOKEN'
```


## Snapshot lifecycle

A snapshot can have several different states. Each state reflects the snapshot's current status.

<details><summary>Snapshot states</summary>

| **State**    | **Description**                                                                                         |
| ------------ | ------------------------------------------------------------------------------------------------------- |
| Pending      | The snapshot creation has been requested.                                                               |
| Building     | The snapshot is being built.                                                                            |
| Pulling      | The snapshot image is being pulled from a registry.                                                     |
| Snapshotting | The snapshot is being created from a sandbox.                                                           |
| Active       | The snapshot is ready to use for creating sandboxes.                                                    |
| Inactive     | The snapshot is deactivated; must be explicitly activated before use.                                   |
| Error        | The snapshot creation failed.                                                                           |
| Build Failed | The snapshot build process failed.                                                                      |
| Removing     | The snapshot is being deleted.                                                                           |

</details>

##### State transitions

A snapshot can transition between states in response to various actions. The following table lists the initial state, target state, and trigger for the transition.

<details><summary>State transitions</summary>

| **Initial state** | **Target state** | **Trigger**                                                                                        |
| ----------------- | ----------------- | --------------------------------------------------------------------------------------------------- |
| Pending           | Building          | A declarative image build starts.                                                                  |
| Pending           | Pulling           | The snapshot image pull starts.                                                                    |
| Pending           | Error             | Snapshot processing fails.                                                                         |
| Pending           | Removing          | A delete is requested.                                                                             |
| Building          | Active            | The build finishes and the snapshot is ready.                                                      |
| Building          | Build Failed      | The image build is rejected.                                                                       |
| Building          | Error             | The build fails or times out.                                                                      |
| Building          | Removing          | A delete is requested.                                                                             |
| Pulling           | Active            | The image pull finishes and the snapshot is ready.                                                 |
| Pulling           | Error             | The image pull fails or times out.                                                                 |
| Pulling           | Removing          | A delete is requested.                                                                             |
| Snapshotting      | Active            | The snapshot from a sandbox finishes and is ready.                                                 |
| Snapshotting      | Error             | The snapshot from a sandbox fails or times out.                                                    |
| Snapshotting      | Removing          | A delete is requested.                                                                             |
| Active            | Inactive          | A deactivate is requested, the organization is suspended, or the deactivation timeout is exceeded. |
| Active            | Removing          | A delete is requested.                                                                             |
| Inactive          | Pending           | An activate is requested.                                                                          |
| Inactive          | Removing          | A delete is requested.                                                                             |
| Error             | Removing          | A delete is requested.                                                                             |
| Build Failed       | Removing          | A delete is requested.                                                                             |

</details>

## Run Docker in a sandbox

Sandboxes can run Docker containers inside them (**Docker-in-Docker**), enabling you to build, test, and deploy containerized applications.

Agents can interact with these services since they run within the same sandbox environment, providing better isolation and security compared to external service dependencies.

- Run databases (PostgreSQL, Redis, MySQL) and other services
- Build and test containerized applications
- Deploy microservices and their dependencies
- Create isolated development environments with full container orchestration

:::note
Docker-in-Docker sandboxes require additional resources due to the Docker daemon overhead. Consider allocating at least 2 vCPU and 4GiB of memory for optimal performance.
:::

##### Create a Docker-in-Docker snapshot

Daytona provides an option to create a snapshot with Docker support using pre-built Docker-in-Docker images as a base or by manually installing Docker in a custom image.

###### Using pre-built images

The following base images are widely used for creating Docker-in-Docker snapshots or can be used as a base for a custom Dockerfile:

- **`docker:28.3.3-dind`**: official Docker-in-Docker image (Alpine-based, lightweight)
- **`docker:28.3.3-dind-rootless`**: rootless Docker-in-Docker for enhanced security
- **`docker:28.3.2-dind-alpine3.22`**: Docker-in-Docker image with Alpine 3.22

**Manual installation**

Alternatively, install Docker manually in a custom Dockerfile:

```dockerfile
FROM ubuntu:22.04
# Install Docker using the official install script
RUN curl -fsSL https://get.docker.com | VERSION=28.3.3 sh -
```

##### Run Docker Compose in a sandbox

Define and run multi-container applications. With Docker-in-Docker enabled in a Daytona sandbox, you can use Docker Compose to orchestrate services like databases, caches, and application containers.

1. Create a Docker-in-Docker snapshot with one of the pre-built images
2. Run Docker Compose services inside a sandbox


```python
from daytona import Daytona, CreateSandboxFromSnapshotParams

# Initialize the Daytona client
daytona = Daytona()

# Create a sandbox from a Docker-in-Docker snapshot
sandbox = daytona.create(CreateSandboxFromSnapshotParams(snapshot='docker-dind'))

# Create a docker-compose.yml file
compose_content = '''
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
'''
sandbox.fs.upload_file(compose_content.encode(), 'docker-compose.yml')

# Start Docker Compose services
result = sandbox.process.exec('docker compose -p demo up -d')
print(result.result)

# Check running services
result = sandbox.process.exec('docker compose -p demo ps')
print(result.result)

# Clean up
sandbox.process.exec('docker compose -p demo down')
```


```typescript
import { Daytona } from '@daytona/sdk'

// Initialize the Daytona client
const daytona = new Daytona()

// Create a sandbox from a Docker-in-Docker snapshot
const sandbox = await daytona.create({ snapshot: 'docker-dind' })

// Create a docker-compose.yml file
const composeContent = `
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
`
await sandbox.fs.uploadFile(Buffer.from(composeContent), 'docker-compose.yml')

// Start Docker Compose services
let result = await sandbox.process.executeCommand('docker compose -p demo up -d')
console.log(result.result)

// Check running services
result = await sandbox.process.executeCommand('docker compose -p demo ps')
console.log(result.result)

// Clean up
await sandbox.process.executeCommand('docker compose -p demo down')
```


```ruby
require 'daytona'

# Initialize the Daytona client
daytona = Daytona::Daytona.new

# Create a sandbox from a Docker-in-Docker snapshot
sandbox = daytona.create(Daytona::CreateSandboxFromSnapshotParams.new(snapshot: 'docker-dind'))

# Create a docker-compose.yml file
compose_content = <<~YAML
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
YAML
sandbox.fs.upload_file(compose_content, 'docker-compose.yml')

# Start Docker Compose services
result = sandbox.process.exec(command: 'docker compose -p demo up -d')
puts result.result

# Check running services
result = sandbox.process.exec(command: 'docker compose -p demo ps')
puts result.result

# Clean up
sandbox.process.exec(command: 'docker compose -p demo down')
```


```go
package main

import (
	"context"
	"fmt"

	"github.com/daytona/clients/sdk-go/pkg/daytona"
	"github.com/daytona/clients/sdk-go/pkg/types"
)

func main() {
	ctx := context.Background()

	// Initialize the Daytona client
	client, _ := daytona.NewDaytona(nil)

	// Create a sandbox from a Docker-in-Docker snapshot
	sandbox, _ := client.Create(ctx, &types.CreateSandboxFromSnapshotParams{
		Snapshot: daytona.Ptr("docker-dind"),
	}, nil)

	// Create a docker-compose.yml file
	composeContent := `
services:
  web:
    image: nginx:alpine
    ports:
      - "8080:80"
`
	sandbox.Fs.UploadFile(ctx, []byte(composeContent), "docker-compose.yml")

	// Start Docker Compose services
	result, _ := sandbox.Process.ExecuteCommand(ctx, "docker compose -p demo up -d", nil)
	fmt.Println(result.Result)

	// Check running services
	result, _ = sandbox.Process.ExecuteCommand(ctx, "docker compose -p demo ps", nil)
	fmt.Println(result.Result)

	// Clean up
	sandbox.Process.ExecuteCommand(ctx, "docker compose -p demo down", nil)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.CreateSandboxFromSnapshotParams;
import io.daytona.sdk.model.ExecuteResponse;

import java.nio.charset.StandardCharsets;

public class App {
    public static void main(String[] args) {
        try (Daytona daytona = new Daytona()) {
            // Create a sandbox from a Docker-in-Docker snapshot
            CreateSandboxFromSnapshotParams params = new CreateSandboxFromSnapshotParams();
            params.setSnapshot("docker-dind");
            Sandbox sandbox = daytona.create(params);

            // Create a docker-compose.yml file
            String composeContent = """
                services:
                  web:
                    image: nginx:alpine
                    ports:
                      - "8080:80"
                """;
            sandbox.fs.uploadFile(composeContent.getBytes(StandardCharsets.UTF_8), "docker-compose.yml");

            // Start Docker Compose services
            ExecuteResponse result = sandbox.getProcess().executeCommand("docker compose -p demo up -d");
            System.out.println(result.getResult());

            // Check running services
            result = sandbox.getProcess().executeCommand("docker compose -p demo ps");
            System.out.println(result.getResult());

            // Clean up
            sandbox.getProcess().executeCommand("docker compose -p demo down");
        }
    }
}
```


## Run Kubernetes in a sandbox

Sandboxes can run a Kubernetes cluster inside the sandbox. Kubernetes runs entirely inside the sandbox and is removed when the sandbox is deleted, keeping environments secure and reproducible.

1. Create a sandbox
2. Install and start a k3s cluster inside the sandbox


```python
from daytona import Daytona, SessionExecuteRequest
import time

# Initialize the Daytona client
daytona = Daytona()

# Create the sandbox instance
sandbox = daytona.create()

# Run the k3s installation script
response = sandbox.process.exec('curl -sfL https://get.k3s.io | sh -')

# Run k3s
session_name = 'k3s-server'
sandbox.process.create_session(session_name)
sandbox.process.execute_session_command(
    session_name,
    SessionExecuteRequest(
        command='sudo /usr/local/bin/k3s server',
        run_async=True,
    ),
)

# Give time to k3s to fully start
time.sleep(30)

# Get all pods
pods = sandbox.process.exec('sudo /usr/local/bin/kubectl get pod -A')
print(pods.result)
```


```typescript
import { Daytona } from '@daytona/sdk'
import { setTimeout } from 'timers/promises'

// Initialize the Daytona client
const daytona = new Daytona()

// Create the sandbox instance
const sandbox = await daytona.create()

// Run the k3s installation script
const response = await sandbox.process.executeCommand(
  'curl -sfL https://get.k3s.io | sh -'
)

// Run k3s
const sessionName = 'k3s-server'
await sandbox.process.createSession(sessionName)
const k3s = await sandbox.process.executeSessionCommand(sessionName, {
  command: 'sudo /usr/local/bin/k3s server',
  async: true,
})

// Give time to k3s to fully start
await setTimeout(30000)

// Get all pods
const pods = await sandbox.process.executeCommand(
  'sudo /usr/local/bin/kubectl get pod -A'
)
console.log(pods.result)
```


```ruby
require 'daytona'

# Initialize the Daytona client
daytona = Daytona::Daytona.new

# Create the sandbox instance
sandbox = daytona.create

# Run the k3s installation script
response = sandbox.process.exec(command: 'curl -sfL https://get.k3s.io | sh -')

# Run k3s
session_name = 'k3s-server'
sandbox.process.create_session(session_name)
sandbox.process.execute_session_command(
  session_id: session_name,
  req: Daytona::SessionExecuteRequest.new(
    command: 'sudo /usr/local/bin/k3s server',
    run_async: true
  )
)

# Give time to k3s to fully start
sleep 30

# Get all pods
pods = sandbox.process.exec(command: 'sudo /usr/local/bin/kubectl get pod -A')
puts pods.result
```


```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/daytona/clients/sdk-go/pkg/daytona"
	"github.com/daytona/clients/sdk-go/pkg/types"
)

func main() {
	ctx := context.Background()

	// Initialize the Daytona client
	client, _ := daytona.NewClient()

	// Create the sandbox instance
	sandbox, _ := client.Create(ctx, types.SnapshotParams{})

	// Run the k3s installation script
	_, _ = sandbox.Process.ExecuteCommand(ctx, "curl -sfL https://get.k3s.io | sh -")

	// Run k3s
	sessionName := "k3s-server"
	_ = sandbox.Process.CreateSession(ctx, sessionName)
	_, _ = sandbox.Process.ExecuteSessionCommand(
		ctx, sessionName, "sudo /usr/local/bin/k3s server", true, false,
	)

	// Give time to k3s to fully start
	time.Sleep(30 * time.Second)

	// Get all pods
	pods, _ := sandbox.Process.ExecuteCommand(ctx, "sudo /usr/local/bin/kubectl get pod -A")
	fmt.Println(pods.Result)
}
```


```java
import io.daytona.sdk.Daytona;
import io.daytona.sdk.Sandbox;
import io.daytona.sdk.model.ExecuteResponse;
import io.daytona.sdk.model.SessionExecuteRequest;

public class App {
    public static void main(String[] args) throws InterruptedException {
        try (Daytona daytona = new Daytona()) {
            // Create the sandbox instance
            Sandbox sandbox = daytona.create();

            // Run the k3s installation script
            sandbox.getProcess().executeCommand("curl -sfL https://get.k3s.io | sh -");

            // Run k3s
            String sessionName = "k3s-server";
            sandbox.getProcess().createSession(sessionName);
            sandbox.getProcess().executeSessionCommand(
                sessionName,
                new SessionExecuteRequest("sudo /usr/local/bin/k3s server", true)
            );

            // Give time to k3s to fully start
            Thread.sleep(30000);

            // Get all pods
            ExecuteResponse pods = sandbox.getProcess().executeCommand(
                "sudo /usr/local/bin/kubectl get pod -A"
            );
            System.out.println(pods.getResult());
        }
    }
}
```
