# Documentation Coding Style

## Where are the docs?

TL;DR version: [`docs`](https://github.com/StackExchange/dnscontrol/tree/master/docs) is the [marketing website](https://dnscontrol.org). [`documentation`](https://github.com/StackExchange/dnscontrol/tree/master/documentation) is the [docs.dnscontrol.org](https://docs.dnscontrol.org/) website. (Yes, the names are backwards!)

**The two websites**

1. <https://dnscontrol.org/>
   * The main website
   * Source code: [`docs`](https://github.com/StackExchange/dnscontrol/tree/master/docs)
   * Mostly "marketing" for the project.
   * Rarely changes.  Updated via GitHub "pages" feature.
2. <https://docs.dnscontrol.org/>
   * Project documentation
   * Source code: [`documentation`](https://github.com/StackExchange/dnscontrol/tree/master/documentation)
   * Users and developer documentation
   * Changes frequently.  Updated via [GitBook](https://www.gitbook.com/)

**The directory structure**

Within the git repo, docs are grouped:

* [`documentation/`](https://github.com/StackExchange/dnscontrol/tree/master/documentation): general docs
* [`documentation/providers/`](https://github.com/StackExchange/dnscontrol/tree/master/documentation/providers/): One file per provider
* [`documentation/functions/`](https://github.com/StackExchange/dnscontrol/tree/master/documentation/functions/): One file per `dnsconfig.js` language feature
* [`documentation/assets/FOO/`](https://github.com/StackExchange/dnscontrol/tree/master/documentation/assets/): Images for page FOO(PNGs only, please!)

## How to add a new page?

1. Add the page to the `documentation` folder (possibly a sub folder)
2. List the page in `SUMMARY.md` so that it will appear in the table of contents, sidebar, etc.

## Documentation previews

> "Preview links are only accessible by GitBook users. We're working on a feature that will allow preview links to be viewable by anyone who accesses the PR." — _[GitBook](https://docs.gitbook.com/product-tour/git-sync/github-pull-request-preview#how-to-access-preview-links)_

## Formatting tips

### General

Break lines every 80 chars.

Include a blank line between paragraphs.

Leave one blank line before and after a heading.

Javascript code should use double quotes (`"`) for strings, not single quotes
(`'`).  They are equivalent but consistency is good.

### Headings

```markdown
#  Title of the page

## Heading

At least one paragraph.

## Subheadings

At least one paragraph.

* **Step 1: Foo**

Description of the step.

* **Step 2: Bar**

Description of the step.

(further sub sub headings are discouraged encouraged)
```

### Code Snippets

See the examples below, for the Markdown syntax click on the 'Source code'.

Long example: (with filename)

{% code title="dnsconfig.js" %}
```javascript
var REG_NONE = NewRegistrar("none");
var DNS_BIND = NewDnsProvider("bind");

D("example.com", REG_NONE, DnsProvider(DNS_BIND),
    A("@", "1.2.3.4")
);
```
{% endcode %}

[Source code](markdown-examples/code/dnsconfig-code-example-with-filename.md?plain=1)

Long example: (without filename)

{% code %}
```javascript
var REG_NONE = NewRegistrar("none");
var DNS_BIND = NewDnsProvider("bind");

D("example.com", REG_NONE, DnsProvider(DNS_BIND),
    A("@", "1.2.3.4")
);
```
{% endcode %}

[Source code](markdown-examples/code/dnsconfig-code-example-without-filename.md?plain=1)

### Hint

Hints are a great way to bring the reader's attention to specific elements in your documentation.

There are 4 different types of hints, and both inline content and formatting are supported.

### Example of a hint

{% hint style="info" %}
**Info hints** are great for showing general information, or providing tips and tricks.
{% endhint %}

 [Source code](markdown-examples/hint/hint-info.md?plain=1)

{% hint style="success" %}
**Success hints** are good for showing positive actions or achievements.
{% endhint %}

 [Source code](markdown-examples/hint/hint-success.md?plain=1)

{% hint style="warning" %}
**Warning hints** are good for showing important information or non-critical warnings.
{% endhint %}

 [Source code](markdown-examples/hint/hint-warning.md?plain=1)

{% hint style="danger" %}
**Danger hints** are good for highlighting destructive actions or raising attention to critical information.
{% endhint %}

 [Source code](markdown-examples/hint/hint-danger.md?plain=1)

{% hint style="info" %}
### This is a heading

This is a line

This is a second <mark style="color:white;background-color:green;">line</mark>
{% endhint %}

### Technical references

#### Mentioning language features

Not every mention to A, CNAME, or function
needs to be a link to the manual for that record type.
However, the first mention on a page should always
be a link.  Others are at the authors digression.

```markdown
The [`PTR`](functions/domain/PTR.md) feature is helpful in LANs.
```

#### Mentioning functions from the Source code

```markdown
The function `GetRegistrarCorrections()` returns...
```

### Links

#### Internal links

```markdown
Blah blah blah [M365_BUILDER](functions/record/M365_BUILDER.md)
```

{% hint style="info" %}
**NOTE**: The `.md` is required.
{% endhint %}

#### Link to another website

Just list the URL.

```markdown
Blah blah blah <https://www.google.com> blah blah.
```

#### Link with anchor text

```markdown
Blah blah blah [a search engine](https://www.google.com) blah blah.
```

## Proofreading

Please spellcheck documents before submitting a PR.

Don't be surprised if Tom rewrites your text.  He often does that to keep the
documentation consistent and make it more approachable by new users.  It's not
[because he has a big ego](https://www.amazon.com/stores/author/B004J0QIVM).
Well, not usually.