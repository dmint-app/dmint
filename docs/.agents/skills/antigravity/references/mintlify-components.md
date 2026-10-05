# Mintlify Component Reference

## Callouts

```mdx
<Note>Tip or extra info.</Note>
<Tip>Best practice or shortcut.</Tip>
<Info>Neutral, contextual info.</Info>
<Warning>Something that could break things.</Warning>
<Danger>Irreversible or destructive action.</Danger>
<Check>Confirmation or success state.</Check>
```

---

## Steps

```mdx
<Steps>
  <Step title="Step Title">
    Step content here. Can include code blocks, images, nested components.
  </Step>
  <Step title="Next Step">
    ...
  </Step>
</Steps>
```

---

## Cards

```mdx
<Card title="Card Title" icon="rocket" href="/link">
  Card description text.
</Card>

<CardGroup cols={2}>
  <Card title="Card 1" icon="bolt" href="/page-1">Description.</Card>
  <Card title="Card 2" icon="shield" href="/page-2">Description.</Card>
</CardGroup>
```

`cols` can be 1, 2, 3, or 4.
Icons are Lucide icon names.

---

## Tabs

```mdx
<Tabs>
  <Tab title="Node.js">
    ```js
    const x = 1;
    ```
  </Tab>
  <Tab title="Python">
    ```python
    x = 1
    ```
  </Tab>
</Tabs>
```

---

## Accordion

```mdx
<AccordionGroup>
  <Accordion title="FAQ Question 1?">
    Answer text here.
  </Accordion>
  <Accordion title="FAQ Question 2?">
    Answer text here.
  </Accordion>
</AccordionGroup>
```

---

## Code Groups

```mdx
<CodeGroup>
  <Code title="install.sh">
    ```bash
    npm install my-package
    ```
  </Code>
  <Code title="install-yarn.sh">
    ```bash
    yarn add my-package
    ```
  </Code>
</CodeGroup>
```

---

## API Reference Components

### ParamField
```mdx
<ParamField path="user_id" type="string" required>
  The unique identifier of the user.
</ParamField>

<ParamField query="limit" type="number" default="20">
  Maximum number of results to return.
</ParamField>

<ParamField body="name" type="string">
  Display name for the resource.
</ParamField>
```
`path` | `query` | `body` | `header` set the parameter location.

### ResponseField
```mdx
<ResponseField name="id" type="string">
  Unique identifier of the created resource.
</ResponseField>

<ResponseField name="data" type="object">
  <Expandable title="data properties">
    <ResponseField name="created_at" type="string">
      ISO 8601 timestamp.
    </ResponseField>
  </Expandable>
</ResponseField>
```

### RequestExample / ResponseExample
```mdx
<RequestExample>
  ```bash cURL
  curl -X POST https://api.example.com/v1/resource \
    -H "Authorization: Bearer TOKEN" \
    -d '{"name": "My Resource"}'
  ```
</RequestExample>

<ResponseExample>
  ```json 200
  {
    "id": "res_123",
    "name": "My Resource"
  }
  ```
</ResponseExample>
```

---

## Frame (for images and iframes)

```mdx
<Frame>
  ![Alt text](/images/screenshot.png)
</Frame>

<Frame type="glass">
  <img src="/images/diagram.png" alt="Architecture diagram" />
</Frame>
```

---

## Tooltip

```mdx
<Tooltip tip="This is the tooltip text.">hover over this</Tooltip>
```

---

## Icon

```mdx
<Icon icon="rocket" size={20} color="#6366f1" />
```

---

## Snippet (Reusable content)

Create `/snippets/my-snippet.mdx`:
```mdx
This is reusable content.
```

Use it:
```mdx
<Snippet file="my-snippet.mdx" />
```

---

## Update (for changelogs)

```mdx
<Update label="v1.2.0" description="January 15, 2024">
  Description of what changed.
</Update>
```
