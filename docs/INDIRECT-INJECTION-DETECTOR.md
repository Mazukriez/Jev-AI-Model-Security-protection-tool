# Indirect prompt-injection detector

`src/detectors/indirect-injection.js` scans content that can arrive through retrieval, file uploads, attachments, web pages, or external APIs. These sources are data, but malicious text inside them may try to act like a higher-priority instruction.

The detector accepts the standard fields (`state`, `question`, `request`) plus source-aware fields: `externalData`, `fileName`, `fileContent`, `attachmentText`, and `retrievedText`. It looks for instruction overrides, agent redirection, secret exfiltration, forced link/file execution, concealment requests, and fake system/developer labels.

This is a heuristic preflight control. It cannot determine whether a document is trustworthy or whether a link is safe. Applications should preserve source labels, isolate file content from system instructions, avoid automatic tool execution, and route `REVIEW` or `BLOCK` results to an explicit policy path.

Example:

```js
import { scan } from '../src/index.js';

const result = scan({
  question: 'Summarize the uploaded file',
  fileName: 'customer-notes.txt',
  fileContent: uploadedText
});
```
