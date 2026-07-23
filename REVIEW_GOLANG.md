# Go-Specific Review Guidelines

These guidelines supplement the general [REVIEW.md](REVIEW.md) with
Go-specific expectations.

## Separating Parsing from I/O

Have the parser accept a string or `io.Reader`, then have a separate function
that opens the file and calls the parser:

```go
// ✅ Good: parser is a pure function, easy to unit test
func parseConfig(data string) (*Config, error) { ... }

func loadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    return parseConfig(string(data))
}
```

## Don't Ignore (Swallow) Errors

Avoid discarding errors with the blank identifier. Most errors should be
returned to the caller. If not, at least log the error:

```go
// ❌ Avoid: error is silently swallowed
_ = doSomething()

// ✅ Good: propagate
if err := doSomething(); err != nil {
    return err
}

// ✅ OK if the error is truly ignorable: log it
if err := doSomething(); err != nil {
    log.Debug("ignoring error", "err", err)
}
```

## Gomega and Test Assertions

We use [gomega](https://github.com/onsi/gomega) for test assertions. Follow
these conventions:

### Use `g.Eventually` for Polling

Gomega's `Eventually` handles polling, timeouts, and failure reporting.

### Return `(T, error)` from `Eventually` Callbacks

Return the specific field you care about and let gomega matchers describe the
expectation declaratively. This produces better failure messages because
gomega can show what the value actually was vs. what was expected.

```go
// ✅ Good: return the field, match with gomega
g.Eventually(func() ([]metav1.Condition, error) {
    var p bootcv1alpha1.BootcNodePool
    err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &p)
    return p.Status.Conditions, err
}).Should(ContainElement(And(
    HaveField("Type", bootcv1alpha1.PoolDegraded),
    HaveField("Status", metav1.ConditionTrue),
    HaveField("Reason", bootcv1alpha1.PoolNodeDegraded),
)))

// ❌ Avoid: assertions inside the callback with Succeed()
g.Eventually(func(g Gomega) {
    var p bootcv1alpha1.BootcNodePool
    g.Expect(k8sClient.Get(ctx, ...)).To(Succeed())
    cond := apimeta.FindStatusCondition(p.Status.Conditions, ...)
    g.Expect(cond).NotTo(BeNil())
    g.Expect(cond.Status).To(Equal(...))
}).Should(Succeed())
```

### Return the Narrowest Type

Extract exactly the field you want to assert on — labels, conditions,
ownerReference — rather than returning the whole object or a `bool`:

```go
// Labels
g.Eventually(func() (map[string]string, error) {
    var n corev1.Node
    err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &n)
    return n.Labels, err
}).Should(HaveKey(bootcv1alpha1.LabelManaged))

// OwnerReference
g.Eventually(func() (*metav1.OwnerReference, error) {
    var bn bootcv1alpha1.BootcNode
    err := k8sClient.Get(ctx, client.ObjectKey{Name: name}, &bn)
    return metav1.GetControllerOf(&bn), err
}).Should(And(Not(BeNil()), HaveField("Name", pool.Name)))
```

### Use Composed Matchers for Struct Assertions

Prefer `HaveField` and `ContainElement(And(...))` to match on struct fields
declaratively rather than manually extracting fields and asserting one by one:

```go
// ✅ Good: declarative, one expression
g.Expect(conditions).To(ContainElement(And(
    HaveField("Type", bootcv1alpha1.PoolDegraded),
    HaveField("Status", metav1.ConditionTrue),
    HaveField("Reason", bootcv1alpha1.PoolInvalidSpec),
)))

// ❌ Avoid: manual lookup + sequential field assertions
cond := apimeta.FindStatusCondition(conditions, bootcv1alpha1.PoolDegraded)
g.Expect(cond).NotTo(BeNil())
g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
g.Expect(cond.Reason).To(Equal(bootcv1alpha1.PoolInvalidSpec))
```

### Assert Specific Errors When Expected

When a test expects a particular error, match on the concrete error type or
value:

```go
// ✅ Good: we know the API server should reject this
g.Expect(err).To(MatchError(apierrors.IsInvalid, "IsInvalid"))
```
