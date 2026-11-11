(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? (module.exports = factory())
    : typeof define === 'function' && define.amd
    ? define(factory)
    : ((global =
        typeof globalThis !== 'undefined' ? globalThis : global || self),
      (global.testSuite = factory()));
})(this, function () {
  return function testSuite(
    DOMPurify,
    window,
    sanitizationTestCases,
    xssTestCases
  ) {
    var document = window.document;
    var jQuery = window.jQuery;

    sanitizationTestCases.forEach((testCase) => {
      QUnit.test(`Sanitization test[${testCase.title}]`, (assert) => {
        assert.contains(
          DOMPurify.sanitize(testCase.payload),
          testCase.expected,
          `Payload: ${testCase.payload}`
        );
      });
    });

    // XSS tests: Native DOM methods (alert() should not be called)
    xssTestCases.forEach((testCase) => {
      QUnit.test(`XSS test: native[${testCase.title}]`, (assert) => {
        document.getElementById('qunit-fixture').innerHTML = DOMPurify.sanitize(
          testCase.payload
        );
        const done = assert.async();
        setTimeout(() => {
          assert.notEqual(window.xssed, true, 'alert() was called');
          // Teardown
          document.getElementById('qunit-fixture').innerHTML = '';
          window.xssed = false;
          done();
        }, 100);
      });
    });
    // XSS tests: jQuery (alert() should not be called)
    xssTestCases.forEach((testCase) => {
      QUnit.test(`XSS test: jQuery[${testCase.title}]`, (assert) => {
        jQuery('#qunit-fixture').html(DOMPurify.sanitize(testCase.payload));
        const done = assert.async();
        setTimeout(() => {
          assert.notEqual(window.xssed, true, 'alert() was called');
          // Teardown
          jQuery('#qunit-fixture').empty();
          window.xssed = false;
          done();
        }, 100);
      });
    });
    // document.write tests to handle FF's strange behavior
    xssTestCases.forEach((testCase) => {
      QUnit.test(
        `XSS test: document.write() into iframe[${testCase.title}]`,
        (assert) => {
          const done = assert.async();
          const iframe = document.createElement('iframe');
          iframe.src = 'about:blank';
          iframe.onload = function () {
            iframe.contentDocument.write(
              '<script>window.alert=function(){top.xssed=true;}</script>' +
                DOMPurify.sanitize(testCase.payload)
            );
            assert.notEqual(
              window.xssed,
              true,
              'alert() was called from document.write()'
            );
            window.xssed = false;
            iframe.parentNode.removeChild(iframe);
            done();
          };
          document.body.appendChild(iframe);
        }
      );
    });

    // Config-Flag Tests
    QUnit.test(
      'Config-Flag tests: KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR',
      function (assert) {
        // KEEP_CONTENT + ALLOWED_TAGS / ALLOWED_ATTR
        assert.equal(
          DOMPurify.sanitize('<iframe>Hello</iframe>', { KEEP_CONTENT: false }),
          ''
        );
        assert.contains(
          DOMPurify.sanitize(
            '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
            {
              ALLOWED_TAGS: ['b', 'q'],
              ALLOWED_ATTR: ['style'],
              KEEP_CONTENT: true,
            }
          ),
          [
            'abc<b style="color:red">123</b><q>123</q>',
            'abc<b style="color: red;">123</b><q>123</q>',
          ]
        );
        assert.equal(
          DOMPurify.sanitize(
            '<a href="#">abc<b style="color:red">123</b><q class="cite">123</b></a>',
            {
              ALLOWED_TAGS: ['b', 'q'],
              ALLOWED_ATTR: ['style'],
              KEEP_CONTENT: false,
            }
          ),
          ''
        );
        assert.equal(
          DOMPurify.sanitize('<a href="#">abc</a>', {
            ALLOWED_TAGS: ['b', 'q'],
            KEEP_CONTENT: false,
          }),
          ''
        );
        assert.equal(
          DOMPurify.sanitize('<form><input name="parentNode"></form>', {
            ALLOWED_TAGS: ['input'],
            KEEP_CONTENT: true,
          }),
          '<input>'
        );
      }
    );
    QUnit.test('Config-Flag tests: ALLOW_SELF_CLOSE_IN_ATTR', function (assert) {
      // ALLOW_SELF_CLOSE_IN_ATTR
      assert.contains(
        DOMPurify.sanitize('<a href="#" class="foo <br/>">abc</a>', {
          ALLOW_SELF_CLOSE_IN_ATTR: false,
        }),
        ['<a href="#">abc</a>',	"<a class=\"foo &lt;br/&gt;\" href=\"#\">abc</a>"]

      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" class="foo <br/>">abc</a>', {
          ALLOW_SELF_CLOSE_IN_ATTR: true,
        }),
        ['<a class="foo <br/>" href="#">abc</a>', "<a class=\"foo &lt;br/&gt;\" href=\"#\">abc</a>"]
      );
    });
    QUnit.test('Config-Flag tests: ALLOW_DATA_ATTR', function (assert) {
      // ALLOW_DATA_ATTR
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-abc"="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
          ALLOW_DATA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-abc="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-abc="foo" href="#">abc</a>',
          '<a href="#" data-abc="foo">abc</a>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-abc-1-2-3="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-abc-1-2-3="foo" href="#">abc</a>',
          '<a href="#" data-abc-1-2-3="foo">abc</a>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-""="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-äöü="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a href="#" data-äöü="foo">abc</a>',
          '<a data-äöü="foo" href="#">abc</a>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<a href="#" data-\u00B7._="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        [
          '<a data-\u00B7._="foo" href="#">abc</a>',
          '<a href="#">abc</a>',
          '<a href="#" data-·._="foo">abc</a>',
        ] // IE11 and Edge throw an InvalidCharacterError
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-\u00B5="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-evil="foo">abc</a>', {
          FORBID_ATTR: ['data-evil'],
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" data-evil="foo">abc</a>', {
          ALLOW_DATA_ATTR: true,
          FORBID_ATTR: ['data-evil'],
        }),
        '<a href="#">abc</a>'
      );
    });
    QUnit.test('Config-Flag tests: ADD_TAGS', function (assert) {
      // ADD_TAGS
      assert.equal(
        DOMPurify.sanitize('<my-component>abc</my-component>', {
          ADD_TAGS: ['my-component'],
        }),
        '<my-component>abc</my-component>'
      );
    });
    QUnit.test('Config-Flag tests: ADD_TAGS + ADD_ATTR', function (assert) {
      // ADD_TAGS + ADD_ATTR
      assert.equal(
        DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
          ADD_TAGS: ['my-component'],
        }),
        '<my-component>abc</my-component>'
      );
      assert.equal(
        DOMPurify.sanitize('<my-component my-attr="foo">abc</my-component>', {
          ADD_TAGS: ['my-component'],
          ADD_ATTR: ['my-attr'],
        }),
        '<my-component my-attr="foo">abc</my-component>'
      );
    });
    QUnit.test(
      'Config-Flag tests: FORBID_CONTENTS + FORBID_TAGS',
      function (assert) {
        // FORBID_CONTENTS + FORBID_TAGS
        assert.equal(
          DOMPurify.sanitize(
            '<div><b>preserve me</b></div><p><b>no not preserve me</b></p>',
            { FORBID_CONTENTS: ['p'], FORBID_TAGS: ['div', 'p'] }
          ),
          '<b>preserve me</b>'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_JQUERY (now inactive, secure by default)',
      function (assert) {
        assert.equal(
          DOMPurify.sanitize(
            '<a>123</a><option><style><img src=x onerror=alert(1)>'
          ),
          '<a>123</a><option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<a>123</a><option><style><img src=x onerror=alert(1)>'
          ),
          '<a>123</a><option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><style></option></select><b><img src=xx: onerror=alert(1)></style></option>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><iframe></select><b><script>alert(1)</script>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<option><iframe></select><b><script>alert(1)</script>'
          ),
          '<option></option>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<b><style><style/><img src=xx: onerror=alert(1)>'
          ),
          '<b></b>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<b><style><style/><img src=xx: onerror=alert(1)>'
          ),
          '<b></b>'
        );
        assert.contains(
          DOMPurify.sanitize('1<template><s>000</s></template>2'),
          ['1<template><s>000</s></template>2', '1<template></template>2', '12']
        );
        assert.contains(DOMPurify.sanitize('<template><s>000</s></template>'), [
          '',
          '<template><s>000</s></template>',
        ]);
        // see https://github.com/cure53/DOMPurify/issues/283
        assert.equal(
          DOMPurify.sanitize('<i>&amp;amp; &lt;</i>'),
          '<i>&amp;amp; &lt;</i>'
        );
      }
    );
    QUnit.test('Config-Flag tests: SAFE_FOR_TEMPLATES', function (assert) {
      //SAFE_FOR_TEMPLATES
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{456}}<b><style><% alert(1) %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-bind="style: alert(1)"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-harmless=""></a>', {
          SAFE_FOR_TEMPLATES: true,
          ALLOW_DATA_ATTR: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a data-harmless=""></a>', {
          SAFE_FOR_TEMPLATES: false,
          ALLOW_DATA_ATTR: false,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>{{123}}{{456}}<b><style><% alert(1) %><% 123 %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>{{123}}abc{{456}}<b><style><% alert(1) %>def<% 123 %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{45{{6}}<b><style><% alert(1)%> %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{45}}6}}<b><style><% <%alert(1) %></style>456</b></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a> <b><style> </style>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123{{<b>456}}</b><style><% alert(1) %></style>456</a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a>123 <b> </b><style> </style>456</a>'
      );
      assert.contains(
        DOMPurify.sanitize(
          '<b>{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}</b>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        ['<b>  </b>', '<b> </b>', '<b> <form><img src="x"></form> </b>']
      );
      assert.contains(
        DOMPurify.sanitize(
          '<b>he{{evil<script>alert(1)</script><form><img src=x name=textContent></form>}}ya</b>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        [
          '<b>he  ya</b>',
          '<b>he </b>',
          '<b>he <form><img src="x"></form> ya</b>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123<% <b>456}}</b><style>{{ alert(1) }}</style>456 %></a>',
          { SAFE_FOR_TEMPLATES: true }
        ),
        '<a>123 <b> </b><style> </style> </a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="}}javascript:alert(1)"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a class="{{999-333}}"></a>', {
          SAFE_FOR_TEMPLATES: true,
        }),
        '<a class=" "></a>'
      );
      assert.equal(
        DOMPurify.sanitize('{{999-333}}', { SAFE_FOR_TEMPLATES: true }),
        ' '
      );
      assert.equal(
        DOMPurify.sanitize('{<x>{333+333}<x>}', { SAFE_FOR_TEMPLATES: true }),
        ' '
      );
    });
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES unterminated template literal mXSS',
      function (assert) {
        // An unterminated `${` has to be neutralized where it occurs. If it
        // survives, the final template-safe pass over the serialized markup
        // pairs it with a `}` from a later node and cuts out everything in
        // between, re-shaping the output into new elements and attributes.
        // See CVE-2025-26791.
        var config = { SAFE_FOR_TEMPLATES: true };
        var parse = function (html) {
          var doc = document.implementation.createHTMLDocument('');
          doc.body.innerHTML = html;
          return doc.body;
        };

        var hasEventHandler = function (root) {
          var elements = root.querySelectorAll('*');
          for (var i = 0; i < elements.length; i++) {
            var attributes = elements[i].attributes;
            for (var j = 0; j < attributes.length; j++) {
              if (/^on/i.test(attributes[j].name)) {
                return true;
              }
            }
          }

          return false;
        };

        // `${` in an attribute paired with `}` in a following text node
        var clean = DOMPurify.sanitize(
          '<img title="${">}" src="x" onerror="alert(1)" y="<b title="q"></b>',
          config
        );
        var body = parse(clean);
        assert.notOk(hasEventHandler(body), 'no event handler attribute');
        assert.equal(body.querySelectorAll('img').length, 1, 'single img');
        assert.notOk(body.querySelector('img').hasAttribute('src'), 'no src');
        assert.equal(body.querySelector('img').getAttribute('title'), ' ');
        assert.equal(
          clean,
          '<img title=" ">}" src="x" onerror="alert(1)" y="<b title="q"></b>'
        );

        // `${` in a text node paired with `}` in a following attribute value
        clean = DOMPurify.sanitize(
          '<b>${</b><a title="}<img src=x onerror=alert(1)>">x</a>',
          config
        );
        body = parse(clean);
        assert.notOk(hasEventHandler(body), 'no event handler attribute');
        assert.equal(body.querySelectorAll('img').length, 0, 'no img element');
        assert.equal(body.querySelectorAll('a').length, 1, 'anchor is kept');
        var anchor = body.querySelector('a');
        assert.equal(
          anchor && anchor.getAttribute('title'),
          '}<img src=x onerror=alert(1)>',
          'anchor title is kept'
        );
        assert.equal(body.querySelector('b').textContent, ' ');

        // `${` assembled from two adjacent text nodes after element removal
        clean = DOMPurify.sanitize(
          '<b>$<foo></foo>{</b><a title="}<img src=x onerror=alert(1)>">x</a>',
          config
        );
        body = parse(clean);
        assert.notOk(hasEventHandler(body), 'no event handler attribute');
        assert.equal(body.querySelectorAll('img').length, 0, 'no img element');
        assert.equal(clean, '<b> ');

        // A complete template literal is still removed
        assert.equal(
          DOMPurify.sanitize('<a>${alert(1)}</a>', config),
          '<a> </a>'
        );
        assert.equal(
          DOMPurify.sanitize('<a title="${alert(1)}"></a>', config),
          '<a title=" "></a>'
        );
      }
    );
    QUnit.test(
      'Config-Flag tests: SAFE_FOR_TEMPLATES with RETURN_DOM and RETURN_DOM_FRAGMENT',
      function (assert) {
        // Template expressions assembled from adjacent text nodes (left over
        // after element removal) have to be stripped when a DOM is returned,
        // just like they are in string mode. See CVE-2026-41239.
        var mustache =
          "{<foo></foo>{constructor.constructor('alert(1)')()}<foo></foo>}";
        var tmplit = '$<foo></foo>{alert(1)}';
        var serializeFragment = function (fragment) {
          var div = fragment.ownerDocument.createElement('div');
          div.appendChild(fragment);
          return div.innerHTML;
        };

        // String mode strips the assembled expression
        assert.equal(
          DOMPurify.sanitize(mustache, { SAFE_FOR_TEMPLATES: true }),
          ' '
        );

        // RETURN_DOM
        var dom = DOMPurify.sanitize(mustache, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.notOk(/\{\{/.test(dom.innerHTML), 'no mustache: ' + dom.innerHTML);
        assert.equal(dom.outerHTML, '<body> </body>');

        dom = DOMPurify.sanitize(tmplit, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.notOk(/\$\{/.test(dom.innerHTML), 'no ${: ' + dom.innerHTML);
        assert.equal(dom.outerHTML, '<body> </body>');

        // RETURN_DOM_FRAGMENT
        var fragment = DOMPurify.sanitize(mustache, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM_FRAGMENT: true,
        });
        assert.equal(fragment.nodeType, 11);
        var html = serializeFragment(fragment);
        assert.notOk(/\{\{/.test(html), 'no mustache in fragment: ' + html);
        assert.equal(html, ' ');

        fragment = DOMPurify.sanitize(tmplit, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM_FRAGMENT: true,
        });
        html = serializeFragment(fragment);
        assert.notOk(/\$\{/.test(html), 'no ${ in fragment: ' + html);
        assert.equal(html, ' ');

        // A DOM node passed in is cleaned as well
        var input = document.createElement('div');
        input.innerHTML = '{<foo></foo>{alert(1)}<foo></foo>}';
        dom = DOMPurify.sanitize(input, {
          SAFE_FOR_TEMPLATES: true,
          RETURN_DOM: true,
        });
        assert.notOk(/\{\{/.test(dom.innerHTML), 'no mustache: ' + dom.innerHTML);
        assert.notOk(/alert/.test(dom.innerHTML), 'no payload: ' + dom.innerHTML);

        // Safe markup is kept and nothing changes without SAFE_FOR_TEMPLATES
        assert.equal(
          DOMPurify.sanitize('<a>123<b>456</b></a>', {
            SAFE_FOR_TEMPLATES: true,
            RETURN_DOM: true,
          }).outerHTML,
          '<body><a>123<b>456</b></a></body>'
        );
        assert.equal(
          DOMPurify.sanitize('{<foo></foo>{1}<foo></foo>}', {
            RETURN_DOM: true,
          }).innerHTML,
          '{{1}}'
        );
      }
    );
    QUnit.test('Config-Flag tests: SANITIZE_DOM', function (assert) {
      // SANITIZE_DOM
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="implementation">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="createNodeIterator">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="getElementById">', {
          SANITIZE_DOM: false,
        }),
        '<img name="getElementById" src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<img src="x" name="getElementById">', {
          SANITIZE_DOM: true,
        }),
        '<img src="x">'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="x" id="location">click</a>', {
          SANITIZE_DOM: true,
        }),
        '<a href="x">click</a>'
      );
      assert.contains(
        DOMPurify.sanitize('<form><input name="attributes"></form>', {
          ADD_TAGS: ['form'],
          SANITIZE_DOM: false,
        }),
        ['', '<form><input name="attributes"></form>']
      );
      assert.contains(
        DOMPurify.sanitize('<form><input name="attributes"></form>', {
          ADD_TAGS: ['form'],
          SANITIZE_DOM: true,
        }),
        ['', '<form><input name="attributes"></form>', '<form><input></form>']
      );
    });
    QUnit.test('Config-Flag tests: SANITIZE_NAMED_PROPS', function (assert) {
      // SANITIZE_NAMED_PROPS
      assert.equal(
        DOMPurify.sanitize('<a id="x"></a>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<a id="user-content-x"></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<form id="x"><input id="y"></form>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<form id="user-content-x"><input id="user-content-y"></form>'
      );
      assert.equal(
        DOMPurify.sanitize('<a id="x"></a><a id="x"></a>', {
          SANITIZE_NAMED_PROPS: true,
        }),
        '<a id="user-content-x"></a><a id="user-content-x"></a>'
      );
    });
    QUnit.test('Config-Flag tests: WHOLE_DOCUMENT', function (assert) {
      //WHOLE_DOCUMENT
      assert.equal(DOMPurify.sanitize('123', { WHOLE_DOCUMENT: false }), '123');
      assert.equal(
        DOMPurify.sanitize('123', { WHOLE_DOCUMENT: true }),
        '<html><head></head><body>123</body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: false,
        }),
        ''
      );
      assert.equal(
        DOMPurify.sanitize('<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head><style>*{color:red}</style></head><body></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('123<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: false,
        }),
        '123<style>*{color:red}</style>'
      );
      assert.equal(
        DOMPurify.sanitize('123<style>*{color:red}</style>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head></head><body>123<style>*{color:red}</style></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<!DOCTYPE html><html><body>123</body></html>', {
          WHOLE_DOCUMENT: true,
        }),
        '<html><head></head><body>123</body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<!DOCTYPE html><html><body>123</body></html>', {
          WHOLE_DOCUMENT: true,
          ADD_TAGS: ['!doctype'],
        }),
        '<!DOCTYPE html>\n<html><head></head><body>123</body></html>'
      );
    });
    QUnit.test('Config-Flag tests: RETURN_DOM', function (assert) {
      //RETURN_DOM
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { RETURN_DOM: true })
          .outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
          RETURN_DOM: true,
        }).outerHTML,
        '<body><a>123<b>456</b></a></body>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        }).outerHTML,
        '<html><head></head><body><a>123<b>456</b></a></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>', {
          RETURN_DOM: true,
          WHOLE_DOCUMENT: true,
        }).outerHTML,
        '<html><head></head><body><a>123<b>456</b></a></body></html>'
      );
      assert.equal(
        DOMPurify.sanitize('123', { RETURN_DOM: true }).outerHTML,
        '<body>123</body>'
      );
    });
    QUnit.test('Config-Flag tests: shadowroot', function (assert) {
      assert.notEqual(
        DOMPurify.sanitize('123', {
          RETURN_DOM: true,
        }).ownerDocument,
        document
      );
      assert.equal(
        DOMPurify.sanitize('123', {
          RETURN_DOM: true,
          ADD_ATTR: ['shadowroot'],
        }).ownerDocument,
        document
      );
      assert.notEqual(
        DOMPurify.sanitize('123', {
          RETURN_DOM_FRAGMENT: true,
        }).ownerDocument,
        document
      );
      assert.equal(
        DOMPurify.sanitize('123', {
          RETURN_DOM_FRAGMENT: true,
          ADD_ATTR: ['shadowroot'],
        }).ownerDocument,
        document
      );
    });
    QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
      //RETURN_DOM_FRAGMENT
      // attempt clobbering
      var fragment = DOMPurify.sanitize(
        'foo<img id="createDocumentFragment">',
        {
          RETURN_DOM_FRAGMENT: true,
        }
      );
      assert.equal(fragment.nodeType, 11);
      assert.notEqual(fragment.ownerDocument, document);
      assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
      // again, but without SANITIZE_DOM
      fragment = DOMPurify.sanitize('foo<img id="createDocumentFragment">', {
        RETURN_DOM_FRAGMENT: true,
        SANITIZE_DOM: false,
      });
      assert.equal(fragment.nodeType, 11);
      assert.notEqual(fragment.ownerDocument, document);
      assert.equal(fragment.firstChild && fragment.firstChild.nodeValue, 'foo');
    });
    QUnit.test('Config-Flag tests: RETURN_DOM_FRAGMENT', function (assert) {
      var xss = `<body><div><template shadowroot=open><img src=x onerror=alert(3)></template></div></body>`;
      var dom_body = DOMPurify.sanitize(xss, { RETURN_DOM: true });
      assert.equal(
        dom_body.outerHTML,
        '<body><div><template><img src="x"></template></div></body>'
      );
    });
    QUnit.test('Config-Flag tests: IN_PLACE', function (assert) {
      //IN_PLACE
      var dirty = document.createElement('a');
      dirty.setAttribute('href', 'javascript:alert(1)');
      var clean = DOMPurify.sanitize(dirty, { IN_PLACE: true });
      assert.equal(dirty, clean); // should return the input node
      assert.equal(dirty.href, ''); // should still sanitize
    });
    QUnit.test(
      'Config-Flag tests: IN_PLACE insecure root-nodes',
      function (assert) {
        //IN_PLACE with insecure root node (script)
        var dirty = document.createElement('script');
        dirty.setAttribute('src', 'data:,alert(1)');
        assert.throws(function () {
          DOMPurify.sanitize(dirty, { IN_PLACE: true });
        });
      }
    );
    QUnit.test(
      'Config-Flag tests: IN_PLACE insecure root-nodes',
      function (assert) {
        //IN_PLACE with insecure root node (iframe)
        var dirty = document.createElement('iframe');
        dirty.setAttribute('src', 'javascript:alert(1)');
        assert.throws(function () {
          DOMPurify.sanitize(dirty, { IN_PLACE: true });
        });
      }
    );

    // GHSA-r47g-fvhr-h676 - parent-less clobbered IN_PLACE root retains
    // attacker-controlled attributes. sanitize() must throw on a clobbered
    // IN_PLACE root, the same way it throws on a forbidden root tag.
    var _formClobberingSupportedR47g = function () {
      var form = document.createElement('form');
      var input = document.createElement('input');
      input.setAttribute('name', 'nodeName');
      form.appendChild(input);
      return typeof form.nodeName !== 'string';
    };
    QUnit.test(
      'GHSA-r47g-fvhr-h676: parent-less clobbered form root throws instead of returning the root with onmouseover intact',
      function (assert) {
        if (!_formClobberingSupportedR47g()) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        var root = document.createElement('form');
        root.setAttribute('onmouseover', 'window.__rooted_h676 = 1');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'nodeName');
        root.appendChild(clobber);

        assert.throws(function () {
          DOMPurify.sanitize(root, { IN_PLACE: true });
        }, 'clobbered parent-less IN_PLACE root must throw');
      }
    );
    QUnit.test(
      'GHSA-r47g-fvhr-h676: each clobbering name covered by _isClobbered triggers the IN_PLACE preamble throw',
      function (assert) {
        if (!_formClobberingSupportedR47g()) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        var clobberNames = [
          'nodeName',
          'setAttribute',
          'namespaceURI',
          'insertBefore',
          'hasChildNodes',
          'childNodes',
          'attributes',
          'textContent',
          'removeChild',
          'removeAttribute',
        ];

        clobberNames.forEach(function (name) {
          var root = document.createElement('form');
          root.setAttribute('onmouseover', 'window.__rooted_' + name + ' = 1');
          var clobber = document.createElement('input');
          clobber.setAttribute('name', name);
          root.appendChild(clobber);

          assert.throws(
            function () {
              DOMPurify.sanitize(root, { IN_PLACE: true });
            },
            /clobbered|forbidden/i,
            'IN_PLACE preamble must throw for clobber name="' + name + '"'
          );
        });
      }
    );
    QUnit.test(
      'GHSA-r47g-fvhr-h676: clobbered form root is rejected regardless of allowlist',
      function (assert) {
        if (!_formClobberingSupportedR47g()) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        var allowedRoot = document.createElement('form');
        var clobberA = document.createElement('input');
        clobberA.setAttribute('name', 'setAttribute');
        allowedRoot.appendChild(clobberA);
        assert.throws(function () {
          DOMPurify.sanitize(allowedRoot, { IN_PLACE: true });
        }, 'allowed-tag clobbered root must throw');

        var forbiddenRoot = document.createElement('form');
        var clobberB = document.createElement('input');
        clobberB.setAttribute('name', 'setAttribute');
        forbiddenRoot.appendChild(clobberB);
        assert.throws(function () {
          DOMPurify.sanitize(forbiddenRoot, {
            IN_PLACE: true,
            FORBID_TAGS: ['form'],
          });
        }, 'forbidden-tag clobbered root must throw');
      }
    );
    QUnit.test(
      'GHSA-r47g-fvhr-h676: clobbered form root throws when attached and with any config',
      function (assert) {
        if (!_formClobberingSupportedR47g()) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        // An attached root is detached by _forceRemove but its attributes are
        // still never inspected, so the caller would get back a form carrying
        // javascript: actions, handlers and template expressions.
        var wrapper = document.createElement('div');
        var root = document.createElement('form');
        root.setAttribute('action', 'javascript:alert(1)');
        root.setAttribute('onfocus', 'window.__rooted_attached = 1');
        root.setAttribute('title', '{{evil}}');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'hasChildNodes');
        root.appendChild(clobber);
        wrapper.appendChild(root);

        assert.throws(function () {
          DOMPurify.sanitize(root, { IN_PLACE: true });
        }, 'attached clobbered IN_PLACE root must throw');

        assert.throws(function () {
          DOMPurify.sanitize(root, {
            IN_PLACE: true,
            SAFE_FOR_TEMPLATES: true,
          });
        }, 'clobbered IN_PLACE root must throw with SAFE_FOR_TEMPLATES');
      }
    );
    QUnit.test(
      'GHSA-r47g-fvhr-h676: unclobbered form root is still sanitized in-place',
      function (assert) {
        // Guard against false positives of the childNodes probe: a form whose
        // children do not shadow any inspected property must not throw.
        var root = document.createElement('form');
        root.setAttribute('onmouseover', 'window.__rooted_plain = 1');
        root.setAttribute('action', 'javascript:alert(1)');
        var input = document.createElement('input');
        input.setAttribute('name', 'username');
        root.appendChild(input);

        var clean = DOMPurify.sanitize(root, { IN_PLACE: true });

        assert.strictEqual(clean, root, 'root is returned in-place');
        assert.notOk(
          root.hasAttribute('onmouseover'),
          'onmouseover removed from root'
        );
        assert.notOk(
          root.hasAttribute('action'),
          'javascript: action removed from root'
        );
        assert.equal(
          root.querySelectorAll('input').length,
          1,
          'harmless input child is kept'
        );
      }
    );
    QUnit.test(
      'GHSA-r47g-fvhr-h676: form clobbered by <select name="childNodes"> is still removed',
      function (assert) {
        if (!_formClobberingSupportedR47g()) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        var form = document.createElement('form');
        var clobber = document.createElement('select');
        clobber.setAttribute('name', 'childNodes');
        form.appendChild(clobber);

        var wrapper = document.createElement('div');
        wrapper.appendChild(form);

        DOMPurify.sanitize(wrapper, { IN_PLACE: true });

        assert.equal(
          wrapper.querySelectorAll('form').length,
          0,
          'form clobbered by <select name="childNodes"> must be removed'
        );
      }
    );
    QUnit.test(
      'GHSA-r47g-fvhr-h676: a parented clobbered form is still sanitized normally (regression guard)',
      function (assert) {
        if (!_formClobberingSupportedR47g()) {
          assert.ok(true, 'SKIP: no form clobbering in this engine');
          return;
        }

        var wrapper = document.createElement('div');
        var form = document.createElement('form');
        form.setAttribute('onmouseover', 'window.__rooted_parented = 1');
        var clobber = document.createElement('input');
        clobber.setAttribute('name', 'nodeName');
        form.appendChild(clobber);
        wrapper.appendChild(form);

        DOMPurify.sanitize(wrapper, { IN_PLACE: true });

        assert.equal(
          wrapper.querySelectorAll('form').length,
          0,
          'parented clobbered form is removed by the iterator-driven path'
        );
      }
    );
    QUnit.test('Config-Flag tests: FORBID_TAGS', function (assert) {
      //FORBID_TAGS
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['b'] }),
        '<a>123456</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
          FORBID_TAGS: ['a', 'b'],
        }),
        '123456789'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', { FORBID_TAGS: ['c'] }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456<script>alert(1)</script></b></a>789', {
          FORBID_TAGS: ['script', 'b'],
        }),
        '<a>123456</a>789'
      );
      assert.equal(
        DOMPurify.sanitize('<a>123<b>456</b></a>', {
          ADD_TAGS: ['b'],
          FORBID_TAGS: ['b'],
        }),
        '<a>123456</a>'
      );
    });
    QUnit.test('Config-Flag tests: FORBID_ATTR', function (assert) {
      //FORBID_ATTR
      assert.equal(
        DOMPurify.sanitize('<a x="1">123<b>456</b></a>', {
          FORBID_ATTR: ['x'],
        }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a class="0" x="1">123<b y="1">456<script>alert(1)</script></b></a>789',
          { FORBID_ATTR: ['x', 'y'] }
        ),
        '<a class="0">123<b>456</b></a>789'
      );
      assert.equal(
        DOMPurify.sanitize('<a y="1">123<b y="1" y="2">456</b></a>', {
          FORBID_ATTR: ['y'],
        }),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(
          '<a>123<b x="1">456<script y="1">alert(1)</script></b></a>789',
          { FORBID_ATTR: ['x', 'y'] }
        ),
        '<a>123<b>456</b></a>789'
      );
    });
    QUnit.test(
      'Config-Param tests: CUSTOM_ELEMENT_HANDLING',
      function (assert) {
        //CUSTOM_ELEMENT_HANDLING
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /^foo-/,
                attributeNameCheck: /baz/,
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /^foo-/,
                attributeNameCheck: /baz/,
                allowCustomizedBuiltInElements: false,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: /-bar$/,
                attributeNameCheck: /.+/,
                allowCustomizedBuiltInElements: true,
              },
            }
          ), // DOMPurify swaps the order of attributes here!
          '<foo-bar forbidden="true" baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: (tagName) => tagName.match(/^foo-/),
                attributeNameCheck: (attr) => attr.match(/baz/),
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
            {
              CUSTOM_ELEMENT_HANDLING: {
                tagNameCheck: (tagName) => tagName.match(/-bar$/),
                attributeNameCheck: (attr) => attr.match(/baz/),
                allowCustomizedBuiltInElements: true,
              },
            }
          ),
          '<foo-bar baz="foobar"></foo-bar><div is=""></div>'
        );
        assert.equal(
          DOMPurify.sanitize(
            '<my-paragraph><span slot="my-text">test</span></my-paragraph>',
            {
              CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /-/u },
            }
          ),
          '<my-paragraph><span slot="my-text">test</span></my-paragraph>'
        );
      }
    );
    QUnit.test('Test dirty being an array', function (assert) {
      assert.equal(
        DOMPurify.sanitize(['<a>123<b>456</b></a>']),
        '<a>123<b>456</b></a>'
      );
      assert.equal(
        DOMPurify.sanitize(['<img src=', 'x onerror=alert(1)>']),
        '<img src=",x">'
      );
    });
    // cross-check that document.write into iframe works properly
    QUnit.test('XSS test: document.write() into iframe', function (assert) {
      const done = assert.async();
      window.xssed = false;
      var iframe = document.createElement('iframe');
      iframe.src = 'about:blank';
      iframe.onload = function () {
        iframe.contentDocument.write(
          '<script>window.alert=function(){parent.xssed=true;}</script><script>alert(1);</script>'
        );
        assert.equal(window.xssed, true, 'alert() was called but not detected');
        window.xssed = false;
        iframe.parentNode.removeChild(iframe);
        done();
      };
      document.body.appendChild(iframe);
    });
    // Check for isSupported property
    QUnit.test('DOMPurify property tests', function (assert) {
      assert.equal(typeof DOMPurify.isSupported, 'boolean');
    });
    // Test with a custom window object
    QUnit.test('DOMPurify custom window tests', function (assert) {
      assert.strictEqual(typeof DOMPurify(null).version, 'string');
      assert.strictEqual(DOMPurify(null).isSupported, false);
      assert.strictEqual(DOMPurify(null).sanitize, undefined);
      assert.strictEqual(typeof DOMPurify({}).version, 'string');
      assert.strictEqual(DOMPurify({}).isSupported, false);
      assert.strictEqual(DOMPurify({}).sanitize, undefined);
      assert.strictEqual(
        typeof DOMPurify({ document: 'not really a document' }).version,
        'string'
      );
      assert.strictEqual(
        DOMPurify({ document: 'not really a document' }).isSupported,
        false
      );
      assert.strictEqual(
        DOMPurify({ document: 'not really a document' }).sanitize,
        undefined
      );
      assert.strictEqual(typeof DOMPurify(window).version, 'string');
      assert.strictEqual(typeof DOMPurify(window).sanitize, 'function');
    });
    // Test to prevent security issues with pre-clobbered DOM
    QUnit.test(
      'sanitize() should not throw if the original document is clobbered _after_ DOMPurify has been instantiated',
      function (assert) {
        var evilNode = document.createElement('div');
        evilNode.innerHTML =
          '<img id="implementation"><img id="createNodeIterator"><img id="importNode"><img id="createElement">';
        document.body.appendChild(evilNode);
        try {
          // tests implementation and createNodeIterator
          var resultPlain = DOMPurify.sanitize('123');
          // tests importNode
          var resultImport = DOMPurify.sanitize('123', {
            RETURN_DOM: true,
            ADD_ATTR: ['shadowroot'],
          });
          // tests createElement
          var resultBody = DOMPurify.sanitize('123<img id="body">');
        } finally {
          // clean up before doing the actual assertions, otherwise qunit/jquery/etc might blow up
          document.body.removeChild(evilNode);
        }
        assert.equal(resultPlain, '123');
        assert.equal(resultImport.ownerDocument, document);
        assert.equal(resultBody, '123<img>');
      }
    );
    // Test to check against a hang in MSIE (#89)
    QUnit.test(
      'sanitize() should not hang on MSIE when hook changes textContent',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.nodeType && node.nodeType === document.TEXT_NODE) {
            node.textContent = 'foo';
          }
          return node;
        });
        var dirty =
          '<div><p>This is a beatufiul text</p><p>This is too</p></div>';
        var modified = '<div><p>foo</p><p>foo</p></div>';
        assert.equal(DOMPurify.sanitize(dirty), modified);
        DOMPurify.removeHooks('afterSanitizeElements');
      }
    );
    // Tests to ensure that a configuration can be set and cleared
    QUnit.test(
      'ensure that a persistent configuration can be set and cleared',
      function (assert) {
        var dirty = '<foobar>abc</foobar>';
        assert.equal(DOMPurify.sanitize(dirty), 'abc');
        DOMPurify.setConfig({ ADD_TAGS: ['foobar'] });
        assert.equal(DOMPurify.sanitize(dirty), '<foobar>abc</foobar>');
        DOMPurify.clearConfig();
        assert.equal(DOMPurify.sanitize(dirty), 'abc');
      }
    );
    // Test to ensure that a hook can add allowed tags / attributes on the fly
    QUnit.test(
      'ensure that a hook can add allowed tags / attributes on the fly',
      function (assert) {
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.nodeName &&
            node.nodeName.match(/^\w+-\w+$/) &&
            !data.allowedTags[data.tagName]
          ) {
            data.allowedTags[data.tagName] = true;
          }
        });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (
            data.attrName &&
            data.attrName.match(/^\w+-\w+$/) &&
            !data.allowedAttributes[data.attrName]
          ) {
            data.allowedAttributes[data.attrName] = true;
          }
        });
        var dirty =
          '<p>HE<iframe></iframe><is-custom onload="alert(1)" super-custom="test" />LLO</p>';
        var modified =
          '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
        assert.equal(DOMPurify.sanitize(dirty), modified);
        DOMPurify.removeHooks('uponSanitizeElement');
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    );
    // Test to ensure that if input[type=file] is badlisted and flagged as an
    // attribute not to keep via hookEvent.keepAttr, it should be removed despite
    // it being an issue of being able to programmatically add it back in Safari.
    QUnit.test(
      'ensure that input[type=file] is removed via hookEvent keepAttr',
      function (assert) {
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (
            node.nodeName == 'INPUT' &&
            node.getAttribute('type') &&
            node.getAttribute('type') == 'file'
          ) {
            data.keepAttr = false;
          }
        });
        var dirty = '<input type="file" />';
        var modified = '<input>';
        if (window.name == 'nodejs') {
          assert.equal(DOMPurify.sanitize(dirty), modified);
        } else {
          assert.expect(0);
        }
        DOMPurify.removeHooks('uponSanitizeAttribute');
      }
    );
    QUnit.test(
      'sanitize() should allow unknown protocols when ALLOW_UNKNOWN_PROTOCOLS is true',
      function (assert) {
        var dirty =
          '<div><a href="spotify:track:12345"><img src="cid:1234567"></a></div>';
        assert.equal(
          dirty,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    QUnit.test(
      'sanitize() should not allow javascript when ALLOW_UNKNOWN_PROTOCOLS is true',
      function (assert) {
        var dirty =
          '<div><a href="javascript:alert(document.title)"><img src="cid:1234567"/></a></div>';
        var modified = '<div><a><img src="cid:1234567"></a></div>';
        assert.equal(
          modified,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    QUnit.test(
      'Regression-Test to make sure #166 stays fixed',
      function (assert) {
        var dirty = '<p onFoo="123">HELLO</p>';
        var modified = '<p>HELLO</p>';
        assert.equal(
          modified,
          DOMPurify.sanitize(dirty, { ALLOW_UNKNOWN_PROTOCOLS: true })
        );
      }
    );

    // Test 1 to check if the element count in DOMPurify.removed is correct
    QUnit.test(
      'DOMPurify.removed should contain one element',
      function (assert) {
        var dirty =
          '<svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
        DOMPurify.sanitize(dirty);
        assert.contains(DOMPurify.removed.length, [1, 2]); // IE removes two
      }
    );

    // Test 2 to check if the element count in DOMPurify.removed is correct
    QUnit.test(
      'DOMPurify.removed should contain two elements',
      function (assert) {
        var dirty =
          '1<script>alert(1)</script><svg onload=alert(1)><filter><feGaussianBlur /></filter></svg>';
        DOMPurify.sanitize(dirty);
        assert.contains(DOMPurify.removed.length, [2, 3]); // IE removed three
      }
    );

    // Test 3 to check if the element count in DOMPurify.removed is correct
    QUnit.test('DOMPurify.removed should be correct', function (assert) {
      var dirty = '<img src=x onerror="alert(1)">';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 1);
    });

    // Test 4 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<a>123{{456}}</a>';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 1);
      }
    );

    // Test 5 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<a>123{{456}}<b>456{{789}}</b></a>';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 2);
      }
    );

    // Test 6 to check that DOMPurify.removed is correct in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should be correct in SAFE_FOR_TEMPLATES mode',
      function (assert) {
        var dirty = '<img src=1 width="{{123}}">';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 1);
      }
    );

    // Test 7 to check that DOMPurify.removed is correct
    QUnit.test('DOMPurify.removed should be correct', function (assert) {
      var dirty = '<option><iframe></select><b><script>alert(1)</script>';
      DOMPurify.sanitize(dirty);
      assert.equal(DOMPurify.removed.length, 1);
    });

    // Test 8 to check that DOMPurify.removed is correct if tags are clean
    QUnit.test(
      'DOMPurify.removed should not contain elements if tags are permitted',
      function (assert) {
        var dirty = '<a>123</a>';
        DOMPurify.sanitize(dirty);
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 9 to check that DOMPurify.removed is correct if the tags and attributes are clean
    QUnit.test(
      'DOMPurify.removed should not contain elements if all tags and attrs are permitted',
      function (assert) {
        var dirty = '<img src=x>';
        DOMPurify.sanitize(dirty);
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 10 to check that DOMPurify.removed does not have false positive elements in SAFE_FOR_TEMLATES mode
    QUnit.test(
      'DOMPurify.removed should not contain elements for valid data in SAFE_FOR_TEMLATES mode',
      function (assert) {
        var dirty = '1';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
          SAFE_FOR_TEMPLATES: true,
        });
        assert.equal(DOMPurify.removed.length, 0);
      }
    );

    // Test 11 to check that DOMPurify.removed does not have false positive elements
    QUnit.test(
      'DOMPurify.removed should not contain elements for valid data',
      function (assert) {
        var dirty = '1';
        DOMPurify.sanitize(dirty, {
          WHOLE_DOCUMENT: true,
        });
        assert.equal(DOMPurify.removed.length, 0);
      }
    );
    // Tests to make sure that the node scanning feature delivers acurate results on all browsers
    QUnit.test(
      'DOMPurify should deliver acurate results when sanitizing nodes 1',
      function (assert) {
        var clean = DOMPurify.sanitize(document.createElement('td'));
        assert.equal(clean, '<td></td>');
      }
    );
    QUnit.test(
      'DOMPurify should deliver accurate results when sanitizing nodes 2',
      function (assert) {
        var clean = DOMPurify.sanitize(document.createElement('td'), {
          RETURN_DOM: true,
        });
        assert.equal(clean.outerHTML, '<body><td></td></body>');
      }
    );
    // Test to make sure that URI_safe attributes can be configured too
    QUnit.test(
      'DOMPurify should allow to define URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
          ADD_URI_SAFE_ATTR: ['typeof'],
        });
        assert.equal(clean, '<b typeof="bla:h">123</b>');
      }
    );
    // Test to make sure that URI_safe attributes don't persist, see #327
    QUnit.test(
      'DOMPurify should not persist URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
          ADD_URI_SAFE_ATTR: ['typeof'],
        });
        var clean = DOMPurify.sanitize('<b typeof="bla:h">123</b>', {
          ALLOWED_ATTR: ['typeof'],
        });
        assert.equal(clean, '<b>123</b>');
      }
    );
    // Test to make sure that URI_safe attributes don't overwrite default, see #366
    QUnit.test(
      'DOMPurify should not overwrite default URI safe attributes',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<div poster="x:y" style="color: red">Test</div>',
          { ADD_URI_SAFE_ATTR: ['poster'] }
        );
        assert.contains(clean, [
          '<div style="color: red" poster="x:y">Test</div>',
          '<div style="color: red;" poster="x:y">Test</div>',
        ]);

        clean = DOMPurify.sanitize(
          '<div poster="x:y" style="color: red">Test</div>'
        );
        assert.contains(clean, [
          '<div style="color: red">Test</div>',
          '<div style="color: red;">Test</div>',
        ]);
      }
    );
    // Test to make sure that empty HTML doesn't return null on MSIE11 (#198)
    QUnit.test(
      "Empty HTML shouldn't return null on MSIE11 in RETURN_DOM_FRAGMENT mode",
      function (assert) {
        var clean = DOMPurify.sanitize('', {
          RETURN_DOM: true,
          RETURN_DOM_FRAGMENT: true,
        });
        assert.equal(typeof clean, 'object');
      }
    );
    // Tests to make sure that FORCE_BODY pushes elements to document.body (#199)
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize('<style>123</style>', {
          FORCE_BODY: true,
        });
        assert.equal(clean, '<style>123</style>');
      }
    );
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize('<script>123</script>', {
          FORCE_BODY: true,
          ADD_TAGS: ['script'],
        });
        assert.equal(clean, '<script>123</script>');
      }
    );
    QUnit.test(
      'FORCE_BODY needs to push some elements to document.body',
      function (assert) {
        var clean = DOMPurify.sanitize(' AAAAA', { FORCE_BODY: true });
        assert.equal(clean, ' AAAAA');
      }
    );
    QUnit.test(
      'Lack of FORCE_BODY still preserves leading whitespace',
      function (assert) {
        var clean = DOMPurify.sanitize(' <b>AAAAA</b>', { FORCE_BODY: false });
        assert.equal(clean, ' <b>AAAAA</b>');
      }
    );
    QUnit.test(
      'Lack of FORCE_BODY needs to push some elements to document.head',
      function (assert) {
        var clean = DOMPurify.sanitize('<style>123</style>', {
          FORCE_BODY: false,
        });
        assert.equal(clean, '');
      }
    );
    // Regression: GHSA-c2j3-45gr-mqc4. A custom element kept via
    // CUSTOM_ELEMENT_HANDLING must run through afterSanitizeElements just
    // like a normal allowlisted element, so a security policy layered in
    // that hook is not silently skipped for kept custom elements.
    QUnit.test(
      'afterSanitizeElements fires on kept custom elements (GHSA-c2j3-45gr-mqc4)',
      function (assert) {
        var seen = [];
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.tagName) {
            seen.push(node.tagName.toLowerCase());
          }
        });
        DOMPurify.sanitize('<x-keep>a</x-keep><div>b</div>', {
          CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ },
        });
        DOMPurify.removeAllHooks();
        assert.ok(
          seen.indexOf('x-keep') !== -1,
          'hook must fire on kept custom element, saw: ' + seen.join(',')
        );
        assert.ok(
          seen.indexOf('div') !== -1,
          'hook still fires on normal element'
        );
      }
    );
    QUnit.test(
      'afterSanitizeElements policy applies uniformly to custom elements (GHSA-c2j3-45gr-mqc4)',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.hasAttribute && node.hasAttribute('data-bio')) {
            node.removeAttribute('data-bio');
          }
        });
        var clean = DOMPurify.sanitize(
          '<div data-bio="&lt;img src=x onerror=alert(1)&gt;"></div>' +
            '<x-bio data-bio="&lt;img src=x onerror=alert(1)&gt;"></x-bio>',
          { CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ } }
        );
        DOMPurify.removeAllHooks();
        assert.equal(clean, '<div></div><x-bio></x-bio>');
      }
    );
    QUnit.test(
      'afterSanitizeElements policy applies to custom elements kept by a tagNameCheck function (GHSA-c2j3-45gr-mqc4)',
      function (assert) {
        var checked = [];
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (node.hasAttribute && node.hasAttribute('data-bio')) {
            node.removeAttribute('data-bio');
          }
        });
        var clean = DOMPurify.sanitize(
          '<div data-bio="&lt;img src=x onerror=alert(1)&gt;"></div>' +
            '<x-bio data-bio="&lt;img src=x onerror=alert(1)&gt;"></x-bio>',
          {
            CUSTOM_ELEMENT_HANDLING: {
              tagNameCheck: function (tagName) {
                checked.push(tagName);
                return tagName.indexOf('x-') === 0;
              },
            },
          }
        );
        DOMPurify.removeAllHooks();
        assert.ok(
          checked.indexOf('x-bio') !== -1,
          'function tagNameCheck was consulted'
        );
        assert.equal(clean, '<div></div><x-bio></x-bio>');
      }
    );
    QUnit.test(
      'afterSanitizeElements can remove a kept custom element (GHSA-c2j3-45gr-mqc4)',
      function (assert) {
        DOMPurify.addHook('afterSanitizeElements', function (node) {
          if (
            node.tagName &&
            node.tagName.toLowerCase() === 'x-evil' &&
            node.parentNode
          ) {
            node.parentNode.removeChild(node);
          }
        });
        var clean = DOMPurify.sanitize('<x-evil>a</x-evil><x-ok>b</x-ok>', {
          CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ },
        });
        DOMPurify.removeAllHooks();
        assert.equal(clean, '<x-ok>b</x-ok>');
      }
    );
    QUnit.test(
      'kept custom element attributes are still sanitized (contract intact) (GHSA-c2j3-45gr-mqc4)',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<x-a onclick="alert(1)" href="javascript:alert(1)"><img src=x onerror=alert(1)></x-a>',
          { CUSTOM_ELEMENT_HANDLING: { tagNameCheck: /^x-/ } }
        );
        assert.notOk(/onclick/i.test(clean), 'event handler stripped');
        assert.notOk(/javascript:/i.test(clean), 'javascript: URI stripped');
        assert.notOk(/onerror/i.test(clean), 'child payload sanitized');
      }
    );
    // Test to make sure that ALLOW_ARIA_ATTR is working as expected (#198)
    QUnit.test('Config-Flag tests: ALLOW_ARIA_ATTR', function (assert) {
      assert.contains(
        DOMPurify.sanitize('<a aria-abc="foo" href="#">abc</a>', {
          ALLOW_ARIA_ATTR: true,
        }),
        [
          '<a aria-abc="foo" href="#">abc</a>',
          '<a href="#" aria-abc="foo">abc</a>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-aöü="foo">abc</a>', {
          ALLOW_ARIA_ATTR: true,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-abc="foo">abc</a>', {
          ALLOW_ARIA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
      assert.equal(
        DOMPurify.sanitize('<a href="#" aria-äöü="foo">abc</a>', {
          ALLOW_ARIA_ATTR: false,
        }),
        '<a href="#">abc</a>'
      );
    });
    QUnit.test('Config-Flag tests: USE_PROFILES', function (assert) {
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: false } }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { html: true } }),
        '<h1>HELLO</h1>'
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math></math>', {
          USE_PROFILES: { html: true, mathMl: true },
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math><mi></mi></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
          FORBID_TAGS: ['mi'],
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<h1>HELLO</h1><math class="foo"><mi></mi></math>', {
          USE_PROFILES: { html: true, mathMl: true },
          FORBID_ATTR: ['class'],
        }),
        [
          '<h1>HELLO</h1>',
          '<h1>HELLO</h1><math><mi></mi></math>',
          '<h1>HELLO</h1><math></math>',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: { bogus: true } }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: 123 }),
        'HELLO'
      );
      assert.equal(
        DOMPurify.sanitize('<h1>HELLO</h1>', { USE_PROFILES: [] }),
        'HELLO'
      );
      assert.contains(
        DOMPurify.sanitize('<svg><rect height="50"></rect></svg>', {
          USE_PROFILES: { svg: true },
        }),
        [
          '',
          '<svg><rect height="50"></rect></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><rect height="50" /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize(
          '<svg><feBlend in="SourceGraphic" mode="multiply" /></svg>',
          {
            USE_PROFILES: { svgFilters: true },
            ADD_TAGS: ['svg'],
          }
        ),
        [
          '<svg><feblend in="SourceGraphic" mode="multiply"></feblend></svg>',
          '<svg><feblend mode="multiply" in="SourceGraphic"></feblend></svg>',
          '<svg><feBlend mode="multiply" in="SourceGraphic"></feBlend></svg>',
          '<svg><feBlend mode="multiply" in="SourceGraphic"></feBlend></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><feBlend in="SourceGraphic" mode="multiply" /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize(
          '<svg><style>.some-class {fill: #fff}</style></svg>',
          {
            USE_PROFILES: { svg: true },
          }
        ),
        [
          '',
          '<svg><style>.some-class {fill: #fff}</style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style>.some-class {fill: #fff}</style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.contains(
        DOMPurify.sanitize('<svg><text>SEE ME</text></svg>', {
          USE_PROFILES: { svg: true },
          KEEP_CONTENT: false,
        }),
        [
          '',
          '<svg><text>SEE ME</text></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><text>SEE ME</text></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]
      );
      assert.equal(
        DOMPurify.sanitize('<span>SEE ME</span>', {
          USE_PROFILES: { html: true },
          KEEP_CONTENT: false,
        }),
        '<span>SEE ME</span>'
      );
      assert.equal(
        DOMPurify.sanitize('<div></div>', {
          USE_PROFILES: { svg: true },
          ADD_TAGS: ['div'],
        }),
        '<div></div>'
      );
      assert.contains(
        DOMPurify.sanitize('<svg keep="me"></svg>', {
          USE_PROFILES: { svg: true },
          ADD_ATTR: ['keep'],
        }),
        [
          '',
          '<svg keep="me"></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" keep="me" />',
        ]
      );
    });
    QUnit.test(
      'Config-Flag tests: USE_PROFILES attribute allowlist does not inherit from prototypes (CVE-2026-65913)',
      function (assert) {
        var dirty = '<img src="x" onerror="alert(1)">';
        var clean;

        // An empty profile leaves ALLOWED_ATTR without any entries. It must
        // not resolve attribute names through Array.prototype either.
        assert.equal(
          DOMPurify.sanitize('<img fill="x" map="x">', {
            USE_PROFILES: {},
            ADD_TAGS: ['img'],
          }),
          '<img>'
        );

        // Polluted Array.prototype must not allow event handlers
        Array.prototype.onerror = true;
        try {
          clean = DOMPurify.sanitize(dirty, {
            USE_PROFILES: {},
            ADD_TAGS: ['img'],
          });
        } finally {
          delete Array.prototype.onerror;
        }

        assert.equal(clean, '<img>');

        // Polluted Object.prototype must not allow event handlers
        Object.prototype.onerror = true;
        try {
          clean = DOMPurify.sanitize(dirty, {
            USE_PROFILES: {},
            ADD_TAGS: ['img'],
            FORBID_ATTR: ['style'],
          });
        } finally {
          delete Object.prototype.onerror;
        }

        assert.equal(clean, '<img>');
      }
    );
    QUnit.test('Config-Flag tests: ALLOWED_URI_REGEXP', function (assert) {
      var tests = [
        {
          test: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
          expected: '<img src="https://i.imgur.com/hkfpOUu.gifv">',
        },
        {
          test: '<img src="http://i.imgur.com/WScAnHr.jpg">',
          expected: '<img src="http://i.imgur.com/WScAnHr.jpg">',
        },
        {
          test:
            '<img src="blob:https://localhost:3000/c4ea3ec6-9f22-4d08-af6f-d79e78a0a7a7">',
          expected: '<img>',
        },
        {
          test: '<a href="mailto:demo@example.com">demo</a>',
          expected: '<a>demo</a>',
        },
      ];
      tests.forEach(function (test) {
        var str = DOMPurify.sanitize(test.test, {
          ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i,
        });
        assert.equal(str, test.expected);
      });
    });
    QUnit.test(
      'Avoid freeze when using tables and ALLOW_TAGS',
      function (assert) {
        var clean = DOMPurify.sanitize('<table><tr><td></td></tr></table>', {
          ALLOW_TAGS: ['table', 'tr', 'td'],
        });
        assert.equal(clean, '<table><tbody><tr><td></td></tr></tbody></table>');
      }
    );
    QUnit.test(
      'Avoid XSS with ALLOW_TAGS permitting noembed, noscript',
      function (assert) {
        var clean = DOMPurify.sanitize(
          "a<noembed><p id='</noembed><img src=x onerror=alert(1)>'></p></noembed>",
          { ADD_TAGS: ['noembed'] }
        );
        assert.contains(clean, [
          'a<noembed><p id=\'</noembed><img src="x">\'&gt;<p></p>',
          'a',
          'a<noembed>&lt;p id=\'</noembed><img src="x">\'&gt;<p></p>',
          'a<noembed><p id="&lt;/noembed&gt;&lt;img src=x onerror=alert(1)&gt;"></p></noembed>',
          'a<noembed></noembed>',
          'a<img src="x">\'&gt;<p></p>',
        ]);
      }
    );
    QUnit.test(
      'Avoid mXSS in Chrome 77 and above using SVG',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg></p><style><g title="</style>');
        assert.contains(clean, [
          '',
          '<svg></svg><p></p><style><g title="</style>',
          '<p></p><style><g title="</style>',
          '<svg></svg><p></p>',
          '<svg><style></style></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><style /></svg></svg>',
        ]);
      }
    );
    QUnit.test(
      'Avoid mXSS in Chrome 77 and above using HTML',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg></p><title><a href="</title>qqq');
        assert.contains(clean, [
          '',
          '<svg></svg><p></p><title>&lt;a href="</title>qqq<img src="">"&gt;',
          '<svg></svg><p></p><title>&lt;a href="</title>qqq',
          '<p></p><title>&lt;a href="</title>qqq',
          '<svg></svg><p></p>qqq',
          '<svg><title></title></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><title /></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg"><title /></svg></svg>',
        ]);
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is true',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
          RETURN_TRUSTED_TYPE: true,
        });
        var type = typeof clean;
        assert.contains(type, ['TrustedHTML', 'string', 'object']);
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is false',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>', {
          RETURN_TRUSTED_TYPE: false,
        });
        var type = typeof clean;
        assert.equal(type, 'string');
      }
    );
    QUnit.test(
      'Test for correct return value when RETURN_TRUSTED_TYPE is not set',
      function (assert) {
        var clean = DOMPurify.sanitize('<b>hello goodbye</b>');
        var type = typeof clean;
        assert.equal(type, 'string');
      }
    );
    QUnit.test(
      'Test for DoS coming from table sanitization 1/2 See #365',
      function (assert) {
        var config = { FORBID_TAGS: ['tbody'] };
        var clean = DOMPurify.sanitize(
          '<table><tbody><tr><td>test</td></tr></tbody></table>',
          config
        );
        assert.equal(
          clean,
          '<table><tbody><tr><td>test</td></tr></tbody></table>'
        );
      }
    );
    QUnit.test(
      'Test for DoS coming from table sanitization 2/2 See #365',
      function (assert) {
        var config = {
          ALLOWED_TAGS: [
            'b',
            'strong',
            'i',
            'italic',
            'div',
            'p',
            'span',
            'ul',
            'li',
            'ol',
            'a',
            'img',
            'br',
            'tr',
            'td',
            'th',
            'table',
            'h1',
            'h2',
            'h3',
            'h4',
            'h5',
            'h6',
          ],
          ALLOW_DATA_ATTR: false,
          ALLOWED_ATTR: ['src', 'class', 'target', 'href'],
        };
        var clean = DOMPurify.sanitize(
          '<table><colgroup><col></col></colgroup><tbody><tr><td >test</td></tr></tbody></table>',
          config
        );
        assert.equal(
          clean,
          '<table><tbody><tr><td>test</td></tr></tbody></table>'
        );
      }
    );
    QUnit.test(
      'Test for less agressive mXSS handling, See #369',
      function (assert) {
        var config = {
          FORBID_TAGS: ['svg', 'math'],
        };
        var clean = DOMPurify.sanitize(
          '<b data-test="<span>content</span>"></b>',
          config
        );
        assert.contains(clean, [
          '<b data-test="<span>content</span>"></b>',
          '<b data-test="&lt;span&gt;content&lt;/span&gt;"></b>',
        ]);
      }
    );
    QUnit.test(
      'Test against mXSS using text integration points and removal 1/2',
      function (assert) {
        var config = {
          FORBID_TAGS: ['mi'],
        };
        var clean = DOMPurify.sanitize(
          '<math><mi><b><style><b title="</style><iframe onload&#x3d;alert(1)<!--"></style>',
          config
        );
        assert.contains(clean, [
          '<math><b><style><b title="</style></b></math>',
          '<math></math>',
          '',
        ]);
      }
    );
    QUnit.test(
      'Test against mXSS using text integration points and removal 2/2',
      function (assert) {
        var config = {
          ADD_TAGS: ['xmp'],
        };
        var clean = DOMPurify.sanitize(
          "x<noframes><svg><b><xmp><b title='</xmp><img>",
          config
        );
        assert.contains(clean, ['x']);
      }
    );
    QUnit.test(
      'Test against insecure behavior in jQUery v3.0 and newer 1/2',
      function (assert) {
        var config = {};
        var clean = DOMPurify.sanitize(
          '<img x="/><img src=x onerror=alert(1)>" y="<x">',
          config
        );
        assert.contains(clean, [
          '<img y="<x" x="/><img src=x onerror=alert(1)>">', // jsdom
          '<img y="<x">',
          '<img y="&lt;x">',
          '<img y="<x">',
          "<img x=\"/><img src=x onerror=alert(1)>\" y=\"<x\">",
		  "<img y=\"&lt;x\" x=\"/&gt;&lt;img src=x onerror=alert(1)&gt;\">"
        ]);
      }
    );
    QUnit.test(
      'Test against insecure behavior in jQUery v3.0 and newer 2/2',
      function (assert) {
        var config = {};
        var clean = DOMPurify.sanitize(
          "a<noscript><p id='><noscript /><img src=x onerror=alert(1)>'></noscript>",
          config
        );
        assert.contains(clean, [
          "a<noscript>&lt;p id='>&lt;noscript />&lt;img src=x onerror=alert(1)>'></noscript>", // jsdom
          'a<noscript><p></p></noscript>',
          'a<p></p>',
          'a',
        ]);
      }
    );
    QUnit.test(
      'Test against data URIs in anchors without proper config flag',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<a href="data:image/gif;base64,123">icon.gif</a>'
        );
        assert.equal(clean, '<a>icon.gif</a>');
      }
    );
    QUnit.test(
      'Test against data URIs in anchors using proper config flag',
      function (assert) {
        var clean = DOMPurify.sanitize(
          '<a href="data:image/gif;base64,123">icon.gif</a>',
          {
            ADD_DATA_URI_TAGS: ['a', 'b'],
          }
        );
        assert.equal(clean, '<a href="data:image/gif;base64,123">icon.gif</a>');
      }
    );
    QUnit.test(
      'Test against Unicode tag names and proper removal',
      function (assert) {
        var clean = DOMPurify.sanitize('<svg><blocKquote>foo</blocKquote>');
        assert.contains(clean, [
          '<svg></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" />',
        ]);

        var clean = DOMPurify.sanitize('<svg><blocKquote>foo</blocKquote>');
        assert.contains(clean, [
          '<svg></svg><blockquote>foo</blockquote>',
          '<svg><blockquote>foo</blockquote></svg>',
          '<svg xmlns="http://www.w3.org/2000/svg" /><blockquote>foo</blockquote>',
        ]);
      }
    );
    QUnit.test(
      'Test protection from prototype pollution attacks 1/2',
      function (assert) {
        const obj = JSON.parse(
          '{"ALLOWED_ATTR":["onerror","src"], "documentMode":9}'
        );
        try {
          for (let [k, v] of Object.entries(obj)) {
            Object.prototype[k] = v;
          }
        } catch (e) {}
        var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
        assert.equal(clean, '<img src="x">');
      }
    );
    QUnit.test(
      'Test protection from prototype pollution attacks 2/2',
      function (assert) {
        var obj = {};
        obj.__proto__.hasOwnProperty = Object;
        obj.constructor.prototype.ALLOWED_ATTR = ["src", "onerror"];
        var clean = DOMPurify.sanitize('<img src=x onerror=alert(1)>');
        assert.equal(clean, '<img src="x">');
      }
    );
    QUnit.test('Test if namespaces are properly enforced', function (assert) {
      var tests = [
        {
          test:
            '<svg><desc><canvas></canvas><textarea></textarea></desc></svg>',
          expected: [
            '<svg><desc></desc></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg"><desc></desc></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><desc /></svg>"
          ],
        },
        {
          test: '<svg><canvas></canvas><textarea></textarea></svg>',
          expected: [
            '<svg></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title /></svg>"
          ],
        },
        {
          test: '<math><canvas></canvas><textarea></textarea></math>',
          expected: ['<math></math>'],
        },
        {
          test: '<math><mi><canvas></canvas><textarea></textarea></mi></math>',
          expected: [
            '<math><mi><canvas></canvas><textarea></textarea></mi></math>',
            '<math></math>',
          ],
        },
        {
          test: '<svg><math></math><title><math></math></title></svg>',
          expected: [
            '<svg><title></title></svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" />',
            '<svg xmlns="http://www.w3.org/2000/svg"><title></title></svg>',
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><title /></svg>"
          ],
        },
        {
          test: '<math><svg></svg><mi><svg></svg></mi></math>',
          expected: [
            '<math><mi><svg></svg></mi></math>',
            '<math><mi><svg xmlns="http://www.w3.org/2000/svg" /></mi></math>',
            '<math></math>',
          ],
        },
        {
          test: '<form><math><mi><mglyph></form><form>',
          expected: [
            '<form><math><mi><mglyph></mglyph></mi></math></form>',
            '<form><math></math></form>',
          ],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test);
        assert.contains(clean, test.expected);
      });
    });
    QUnit.test('Config-Flag tests: NAMESPACE', function (assert) {
      var tests = [
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [
            '<polyline points="0 0"></polyline>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0 0"/>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0,0" />',
            '',
          ],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: ['', '<polyline points="0 0"></polyline>'], // IE10
        },
        {
          test: '<mi></mi>',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: [
            '<mi></mi>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML"></mi>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML"/>',
            '<mi xmlns="http://www.w3.org/1998/Math/MathML" />',
            '',
          ],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: ['', '<polyline points="0 0"></polyline>'], // IE10
        },
        {
          test: '<mi></mi>',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: [''],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });
    QUnit.test('Config-Flag tests: ALLOWED_NAMESPACES', function (assert) {
      const tests = [
        // Test when ALLOWED_NAMESPACES is not set, result is empty for XML with custom namespace
        {
          test:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name></library>',
          config: {
            ALLOWED_TAGS: ['#text', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected: '',
        },
        // Test with one custom namespace at the root (ie. all sub-nodes will inherit that namespace)
        {
          test:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.ibm.com/library'],
            ALLOWED_TAGS: ['#text', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><name>Library 1</name></library>',
        },
        // Test with one custom namespace at sub-node (root will default to HTML_NAMESPACE and should be kept)
        {
          test:
            '<city><library xmlns="http://www.ibm.com/library"><name>Library 1</name><dirty onload="alert()" /></library></city>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.w3.org/1999/xhtml', 'http://www.ibm.com/library'],
            ALLOWED_TAGS: ['#text', 'city', 'library', 'name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<city xmlns="http://www.w3.org/1999/xhtml"><library xmlns="http://www.ibm.com/library"><name>Library 1</name></library></city>',
        },
        // Test removal of namespaces not listed in ALLOWED_NAMESPACES when input has multiple namespaces
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books"><bk:name>Library 1</bk:name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: ['http://www.ibm.com/library'],
            ALLOWED_TAGS: ['library', 'bk:name'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected: ['<library xmlns="http://www.ibm.com/library"/>', '<library xmlns="http://www.ibm.com/library" />']
        },
        // Test with multiple custom namespaces and prefixes in input
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><bk:name>Library 1<m:properties>Other Properties</m:properties></bk:name><dirty onload="alert()" /></library>',
          config: {
            ALLOWED_NAMESPACES: [
              'http://www.ibm.com/library',
              'urn:loc.gov:books',
              'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
            ],
            ALLOWED_TAGS: ['#text', 'library', 'bk:name', 'm:properties'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><bk:name xmlns:bk="urn:loc.gov:books">Library 1<m:properties xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata">Other Properties</m:properties></bk:name></library>',
        },
        // Test removal of elements mentioned in FORBID_TAGS even if their namespaces are allow-listed
        {
          test:
            '<library xmlns="http://www.ibm.com/library" xmlns:bk="urn:loc.gov:books" xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><bk:name>Library 1<m:properties>Other Properties</m:properties></bk:name><dirty onload="alert()" /></library>',
          config: {
            ADD_TAGS: ['library', 'bk:name'],
            ALLOWED_NAMESPACES: [
              'http://www.ibm.com/library',
              'urn:loc.gov:books',
              'http://schemas.microsoft.com/ado/2007/08/dataservices/metadata',
            ],
            FORBID_TAGS: ['m:properties'],
            KEEP_CONTENT: false,
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          },
          expected:
            '<library xmlns="http://www.ibm.com/library"><bk:name xmlns:bk="urn:loc.gov:books">Library 1</bk:name></library>',
        },
      ];
      tests.forEach(function (test) {
        assert.contains(DOMPurify.sanitize(test.test, test.config), test.expected);
      });
    });
    QUnit.test('Config-Flag tests: PARSER_MEDIA_TYPE', function (assert) {
      const tests = [
        {
          test: '<A href="#">invalid</A><a TITLE="title" href="#">valid</a>',
          expected: {
            '': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'Application/xhtml+xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'application/xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'application/xhtml+xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              'invalid<a xmlns="http://www.w3.org/1999/xhtml" href="#">valid</a>',
              'invalid<a xmlns="http://www.w3.org/1999/xhtml" href="#" TITLE="title">valid</a>',
            ],
            'text/html': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
            'text/xml': [
              '<a href="#">invalid</a><a href="#" title="title">valid</a>',
              '<a href="#">invalid</a><a title="title" href="#">valid</a>',
            ],
          },
        },
        {
          config: {
            WHOLE_DOCUMENT: true,
          },
          test: '<A href="#">invalid</A><a TITLE="title" href="#">valid</a>',
          expected: {
            'text/html': [
              '<html><head></head><body><a href="#">invalid</a><a href="#" title="title">valid</a></body></html>',
              '<html><head></head><body><a href="#">invalid</a><a title="title" href="#">valid</a></body></html>',
            ],
            'application/xhtml+xml': [
              '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>invalid<a href="#">valid</a></body></html>',
              '<html xmlns="http://www.w3.org/1999/xhtml"><head /><body>invalid<a href="#">valid</a></body></html>',
              '<html xmlns="http://www.w3.org/1999/xhtml"><head></head><body>invalid<a href="#" TITLE="title">valid</a></body></html>',
            ],
          },
        },
      ];
      tests.forEach(function (test) {
        Object.keys(test.expected).forEach(function (type) {
          var config = test.config || {};
          config.PARSER_MEDIA_TYPE = type;
          var clean = DOMPurify.sanitize(test.test, config);
          assert.contains(clean, test.expected[type]);
        });
      });
    });

    QUnit.test(
      'Config-Flag tests: PARSER_MEDIA_TYPE + ALLOWED_TAGS/ALLOWED_ATTR',
      function (assert) {
        assert.contains(
          DOMPurify.sanitize(
            '<a href="#">abc</a><CustomTag customattr="bar" CustomAttr="foo"/>',
            {
              PARSER_MEDIA_TYPE: 'application/xhtml+xml',
              ALLOWED_TAGS: ['a', 'CustomTag'],
              ALLOWED_ATTR: ['href', 'CustomAttr'],
            }
          ),
          [
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo"></CustomTag>',
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo" customattr="foo"></CustomTag>',
            '<a xmlns="http://www.w3.org/1999/xhtml" href="#">abc</a><CustomTag xmlns="http://www.w3.org/1999/xhtml" CustomAttr="foo" />'
          ]
        );
      }
    );

    QUnit.test('Test invalid xml', function (assert) {
      var tests = [
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: ['', '<!-->'],
        },
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/1998/Math/MathML' },
          expected: ['', '<!-->'],
        },
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: [''],
        },
        {
          test: '',
          config: {},
          expected: [''],
        },
        {
          test: '<!-->',
          config: { NAMESPACE: 'http://www.w3.org/1999/xhtml' },
          expected: ['', '<!-->'],
        },
        {
          test: '<!-->',
          config: {},
          expected: ['', '<!-->'],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });

    QUnit.test(
      'Test namespace default to html after other namespace been used',
      function (assert) {
        var tests = [
          {
            test: '<br>',
            config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
            expected: ['', '<br>'],
          },
          {
            test: '<br>',
            config: {},
            expected: ['<br>'],
          },
        ];
        tests.forEach(function (test) {
          var clean = DOMPurify.sanitize(test.test, test.config);
          assert.contains(clean, test.expected);
        });
      }
    );

    QUnit.test('Test non-html input after empty input', function (assert) {
      var tests = [
        {
          test: '',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [''],
        },
        {
          test: '<polyline points="0 0"></polyline>',
          config: { NAMESPACE: 'http://www.w3.org/2000/svg' },
          expected: [
            '<polyline points="0 0"></polyline>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0 0"/>',
            '<polyline xmlns="http://www.w3.org/2000/svg" points="0,0" />',
            '',
          ],
        },
      ];
      tests.forEach(function (test) {
        var clean = DOMPurify.sanitize(test.test, test.config);
        assert.contains(clean, test.expected);
      });
    });

    QUnit.test('removeHook returns hook function', function (assert) {
      const entryPoint = 'afterSanitizeAttributes';
      const dirty = '<div class="hello"></div>';
      const expected = '<div class="world"></div>';

      DOMPurify.addHook(entryPoint, function (node) {
        return node.setAttribute('class', 'world');
      });
      assert.equal(DOMPurify.sanitize(dirty), expected);

      // remove hook and keep it
      const hookFunction = DOMPurify.removeHook(entryPoint);
      assert.equal(DOMPurify.sanitize(dirty), dirty);

      // set the same hook
      DOMPurify.addHook(entryPoint, hookFunction);
      assert.equal(DOMPurify.sanitize(dirty), expected);

      // Teardown
      DOMPurify.removeHooks(entryPoint);
    });

    // -------------------------------------------------------------------
    // The allowlists are handed to the uponSanitize* hooks by reference (as
    // data.allowedTags / data.allowedAttributes), so a hook that widens them
    // - the documented in-call widening pattern - used to mutate the shared,
    // module-level set: the widening leaked into every later sanitize() call.
    // The guard clones the sets per walk, on both config paths (the per-call
    // path and the persistent setConfig() path). (GHSA-cmwh-pvxp-8882)
    // -------------------------------------------------------------------

    QUnit.test(
      'default config: attribute hook does not poison later calls',
      function (assert) {
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          // A trusted element widens onerror for its own call.
          assert.ok(
            DOMPurify.sanitize(
              '<img data-trusted="1" src="x" onerror="ok()">'
            ).indexOf('onerror') !== -1,
            'in-call widening works for the trusted element'
          );

          // A later untrusted call must NOT inherit the widened attribute.
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'untrusted call after trusted render strips onerror'
          );

          // Repeated calls must stay clean (no accumulated clone state).
          for (var i = 0; i < 5; i++) {
            assert.equal(
              DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
              '<img src="x">',
              'repeated untrusted call ' + i + ' stays clean'
            );
          }
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
        }
      }
    );

    QUnit.test(
      'default config: element hook does not poison later calls',
      function (assert) {
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.getAttribute &&
            node.getAttribute('data-trusted') === '1' &&
            data.allowedTags
          ) {
            data.allowedTags['bogus-tag'] = true;
          }
        });

        try {
          assert.ok(
            DOMPurify.sanitize(
              '<div data-trusted="1"><bogus-tag>abc</bogus-tag></div>'
            ).indexOf('bogus-tag') !== -1,
            'in-call widening works for the trusted element'
          );

          assert.equal(
            DOMPurify.sanitize('<bogus-tag>abc</bogus-tag>'),
            'abc',
            'untrusted <bogus-tag> not allowed after trusted render'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeElement');
        }
      }
    );

    // -------------------------------------------------------------------
    // Persistent-config path (setConfig). sanitize() skips _parseConfig once
    // setConfig() has run, so the sets are not re-derived per call: a hook
    // write to data.allowedAttributes would mutate the allowlist for the
    // instance lifetime, across calls and elements. The guard is applied on
    // every sanitize() call for both config paths. (GHSA-cmwh-pvxp-8882)
    // -------------------------------------------------------------------

    QUnit.test(
      'setConfig: attribute hook does not poison later calls',
      function (assert) {
        DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          // A trusted element widens onerror for its own call.
          assert.ok(
            DOMPurify.sanitize(
              '<img data-trusted="1" src="x" onerror="ok()">'
            ).indexOf('onerror') !== -1,
            'in-call widening works for the trusted element under setConfig'
          );

          // A later untrusted call must NOT inherit the widened attribute.
          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'untrusted call after trusted render strips onerror'
          );

          // Repeated calls must stay clean (no accumulated clone state).
          for (var i = 0; i < 5; i++) {
            assert.equal(
              DOMPurify.sanitize('<img src="x" onerror="alert(' + i + ')">'),
              '<img src="x">',
              'repeated untrusted call ' + i + ' stays clean'
            );
          }
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
          DOMPurify.clearConfig();
        }
      }
    );

    QUnit.test(
      'setConfig: element hook does not poison later calls',
      function (assert) {
        DOMPurify.setConfig({ ALLOWED_TAGS: ['span'], ALLOWED_ATTR: [] });
        DOMPurify.addHook('uponSanitizeElement', function (node, data) {
          if (
            node.getAttribute &&
            node.getAttribute('data-trusted') === '1' &&
            data.allowedTags
          ) {
            data.allowedTags['img'] = true;
          }
        });

        try {
          DOMPurify.sanitize('<span data-trusted="1"><img src="x"></span>');

          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '',
            'untrusted <img> not allowed after trusted render under setConfig'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeElement');
          DOMPurify.clearConfig();
        }
      }
    );

    QUnit.test(
      'setConfig: clearConfig restores a clean state',
      function (assert) {
        DOMPurify.setConfig({ ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] });
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          DOMPurify.sanitize('<img data-trusted="1" src="x" onerror="ok()">');

          DOMPurify.clearConfig();

          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">'),
            '<img src="x">',
            'default-cfg call after clearConfig strips onerror'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
          DOMPurify.clearConfig();
        }
      }
    );

    QUnit.test(
      'reused config object: attribute hook does not poison later calls',
      function (assert) {
        // The parsed config is handed to hooks as their third argument, so a
        // caller can pass it straight back into sanitize(); _parseConfig then
        // returns early without re-deriving the sets.
        var seenConfig = null;
        DOMPurify.addHook('uponSanitizeAttribute', function (node, data, cfg) {
          seenConfig = cfg;
          if (node.getAttribute && node.getAttribute('data-trusted') === '1') {
            data.allowedAttributes['onerror'] = true;
          }
        });

        try {
          var config = { ALLOWED_TAGS: ['img'], ALLOWED_ATTR: ['src'] };
          assert.ok(
            DOMPurify.sanitize(
              '<img data-trusted="1" src="x" onerror="ok()">',
              config
            ).indexOf('onerror') !== -1,
            'in-call widening works for the trusted element'
          );
          assert.ok(seenConfig, 'the hook received the parsed config object');

          assert.equal(
            DOMPurify.sanitize('<img src="x" onerror="alert(1)">', seenConfig),
            '<img src="x">',
            'reusing the parsed config object does not inherit onerror'
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
        }
      }
    );

    // -------------------------------------------------------------------
    // The hooks registry is a plain object, so an unknown entry point such
    // as '__proto__' used to resolve off the prototype chain and arrayPush
    // then wrote to Object.prototype. (GHSA-cmwh-pvxp-8882)
    // -------------------------------------------------------------------

    QUnit.test(
      'addHook ignores unknown entry points and does not pollute Object.prototype',
      function (assert) {
        var hookFunction = function () {};

        try {
          DOMPurify.addHook('__proto__', hookFunction);

          assert.equal(
            {}.length,
            undefined,
            'Object.prototype.length was not created'
          );
          assert.equal({}[0], undefined, 'Object.prototype[0] was not created');
          assert.equal([].length, 0, 'Array.prototype was not affected');

          // Unknown entry points are ignored, not thrown on.
          DOMPurify.addHook('constructor', hookFunction);
          DOMPurify.addHook('notAHook', hookFunction);
          assert.equal(
            DOMPurify.removeHook('__proto__'),
            undefined,
            'removeHook on an unknown entry point returns undefined'
          );
          DOMPurify.removeHooks('__proto__');
          assert.equal(
            {}.length,
            undefined,
            'Object.prototype still untouched after removeHook(s)'
          );

          // Real hooks keep working.
          DOMPurify.addHook('afterSanitizeAttributes', function (node) {
            if (node.setAttribute) {
              node.setAttribute('class', 'world');
            }
          });
          assert.equal(
            DOMPurify.sanitize('<div class="hello"></div>'),
            '<div class="world"></div>',
            'known entry points are still registered'
          );
        } finally {
          DOMPurify.removeHooks('afterSanitizeAttributes');
          delete Object.prototype[0];
          delete Object.prototype.length;
        }
      }
    );

    // -------------------------------------------------------------------
    // SVG <animate>/<set> with attributeName="href" swaps a sanitized href
    // for an attacker-controlled javascript: URL after sanitization, so
    // such attributeName values are dropped even when animations are
    // allowed via ADD_TAGS.
    // -------------------------------------------------------------------

    QUnit.test(
      'Animated href test: attributeName targeting href is removed even when animations are allowed',
      function (assert) {
        var hrefAttr = /attributename\s*=\s*["']?[^"'>]*href/i;
        var dirty =
          '<svg><a><animate attributeName="href" values="x;javascript:alert(1)"></animate>' +
          '<animate attributeName="xlink:href" values="x;javascript:alert(2)"></animate>' +
          '<text y="20">x</text></a></svg>';
        var clean = DOMPurify.sanitize(dirty, { ADD_TAGS: ['animate'] });
        assert.notOk(
          hrefAttr.test(clean),
          'attributeName=href removed: ' + clean
        );
        assert.ok(
          /<animate/i.test(clean),
          'allowed animate element itself is kept: ' + clean
        );

        var setClean = DOMPurify.sanitize(
          '<svg><a><set attributeName="href" to="javascript:alert(3)"></set>' +
            '<text y="20">x</text></a></svg>',
          { ADD_TAGS: ['set'] }
        );
        assert.notOk(
          hrefAttr.test(setClean),
          'attributeName=href removed from set: ' + setClean
        );
        assert.ok(
          /<set/i.test(setClean),
          'allowed set element is kept: ' + setClean
        );

        var benign = DOMPurify.sanitize(
          '<svg><rect><animate attributeName="width" values="1;2"></animate></rect></svg>',
          { ADD_TAGS: ['animate'] }
        );
        assert.ok(
          /attributename\s*=\s*["']?width/i.test(benign),
          'non-href attributeName is kept: ' + benign
        );

        var xhtml = DOMPurify.sanitize(
          '<svg xmlns="http://www.w3.org/2000/svg"><a><animate attributeName="href" values="x;javascript:alert(4)"></animate></a></svg>',
          {
            ADD_TAGS: ['animate'],
            ADD_ATTR: ['attributeName'],
            PARSER_MEDIA_TYPE: 'application/xhtml+xml',
          }
        );
        assert.notOk(
          hrefAttr.test(xhtml),
          'attributeName=href removed in XHTML mode: ' + xhtml
        );
        assert.ok(
          /<animate/i.test(xhtml),
          'animate element is kept in XHTML mode: ' + xhtml
        );

        try {
          DOMPurify.addHook('uponSanitizeAttribute', function (node, data) {
            data.forceKeepAttr = true;
          });
          var forced = DOMPurify.sanitize(dirty, { ADD_TAGS: ['animate'] });
          assert.notOk(
            hrefAttr.test(forced),
            'attributeName=href removed even with forceKeepAttr: ' + forced
          );
        } finally {
          DOMPurify.removeHooks('uponSanitizeAttribute');
        }
      }
    );

    // ---------------------------------------------------------------------------
    // GHSA-hpcv-96wg-7vj8 - cross-realm IN_PLACE sanitization. Foreign-realm
    // nodes (e.g. <form>, <template> from a same-origin iframe document) reach
    // DOMPurify via the realm-agnostic _isNode check at the entry point, but
    // several downstream security branches used to gate on `instanceof X`
    // against parent-realm constructors. Each gate short-circuited to false
    // for foreign-realm objects and the relevant sanitization branch was
    // skipped: form clobbering went undetected, <template>.content was never
    // walked, and the namespace check was never applied.
    //
    // These tests need a same-origin iframe document whose window has its own
    // DOM constructors. They skip if the environment can't provide one.
    // ---------------------------------------------------------------------------
    var _withForeignRealmDocHpcv = function (callback) {
      if (!document.body || typeof document.createElement !== 'function') {
        return false;
      }

      var iframe = document.createElement('iframe');
      document.body.appendChild(iframe);
      try {
        var foreignDoc = iframe.contentDocument;
        var foreignWin = iframe.contentWindow;
        if (
          !foreignDoc ||
          !foreignWin ||
          typeof foreignWin.Node !== 'function' ||
          foreignWin.Node === window.Node
        ) {
          return false;
        }

        callback(foreignDoc, foreignWin);
        return true;
      } finally {
        iframe.parentNode.removeChild(iframe);
      }
    };

    // Does the foreign realm implement HTMLFormElement
    // [LegacyOverrideBuiltIns]? jsdom does not, so there is nothing to
    // detect there; real browsers do.
    var _foreignFormClobbersHpcv = function (idoc) {
      var form = idoc.createElement('form');
      var input = idoc.createElement('input');
      input.setAttribute('name', 'attributes');
      form.appendChild(input);
      return form.attributes === input;
    };

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: cross-realm clobbered form root throws on IN_PLACE',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          if (!_foreignFormClobbersHpcv(idoc)) {
            assert.ok(
              true,
              'SKIP: foreign realm does not implement form clobbering'
            );
            return;
          }

          var foreignForm = idoc.createElement('form');
          foreignForm.setAttribute('onmouseover', 'window.__hpcv_form_xss = 1');
          var clobber = idoc.createElement('input');
          clobber.setAttribute('name', 'attributes');
          foreignForm.appendChild(clobber);

          // Pre-fix `instanceof HTMLFormElement` was false for the foreign
          // form, so it was not flagged and the attribute walk read the
          // clobbered .attributes, leaving onmouseover intact.
          assert.throws(
            function () {
              DOMPurify.sanitize(foreignForm, { IN_PLACE: true });
            },
            /clobbered|forbidden/i,
            'foreign-realm clobbered form must throw on IN_PLACE'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: each clobbering name on a cross-realm form root triggers the IN_PLACE throw',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          if (!_foreignFormClobbersHpcv(idoc)) {
            assert.ok(
              true,
              'SKIP: foreign realm does not implement form clobbering'
            );
            return;
          }

          var clobberNames = [
            'nodeName',
            'setAttribute',
            'namespaceURI',
            'insertBefore',
            'hasChildNodes',
            'childNodes',
            'attributes',
            'textContent',
            'removeChild',
            'removeAttribute',
          ];

          clobberNames.forEach(function (name) {
            var root = idoc.createElement('form');
            root.setAttribute('onmouseover', 'window.__hpcv_' + name + ' = 1');
            var clobber = idoc.createElement('input');
            clobber.setAttribute('name', name);
            root.appendChild(clobber);

            assert.throws(
              function () {
                DOMPurify.sanitize(root, { IN_PLACE: true });
              },
              /clobbered|forbidden/i,
              'IN_PLACE must throw for cross-realm clobber name="' + name + '"'
            );
          });
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: cross-realm form with clobbered nodeType is refused in-place, not stringified',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          var root = idoc.createElement('form');
          root.setAttribute('onmouseover', 'window.__hpcv_nodetype = 1');
          var clobber = idoc.createElement('input');
          clobber.setAttribute('name', 'nodeType');
          root.appendChild(clobber);

          if (typeof root.nodeType === 'number') {
            assert.ok(
              true,
              'SKIP: foreign realm does not implement form clobbering'
            );
            return;
          }

          // Pre-fix the duck-typed _isNode read the clobbered nodeType of
          // the foreign-realm form (the same-realm instanceof short-circuit
          // does not apply), reported it as a non-node, and sanitize()
          // stringified it - returning a string and leaving the caller's
          // form, onmouseover included, untouched.
          // _isNode now recognises the form as a node, and the nodeType
          // probe in _isClobbered (GHSA-76mc-f452-cxcm) flags it as
          // clobbered, so the IN_PLACE preamble refuses the root the same
          // way it refuses any other clobbered form root
          // (GHSA-r47g-fvhr-h676) instead of returning a string.
          var returned;
          assert.throws(
            function () {
              returned = DOMPurify.sanitize(root, { IN_PLACE: true });
            },
            /clobbered/i,
            'nodeType-clobbered foreign-realm IN_PLACE root must throw'
          );
          assert.notEqual(
            typeof returned,
            'string',
            'sanitize() did not stringify the foreign-realm root'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: parented cross-realm clobbered form is removed',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          if (!_foreignFormClobbersHpcv(idoc)) {
            assert.ok(
              true,
              'SKIP: foreign realm does not implement form clobbering'
            );
            return;
          }

          var wrapper = idoc.createElement('div');
          var form = idoc.createElement('form');
          form.setAttribute('onmouseover', 'window.__hpcv_parented = 1');
          var clobber = idoc.createElement('input');
          clobber.setAttribute('name', 'attributes');
          form.appendChild(clobber);
          wrapper.appendChild(form);

          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          assert.equal(
            wrapper.getElementsByTagName('form').length,
            0,
            'foreign-realm clobbered form must be removed'
          );
          assert.notOk(
            /onmouseover/i.test(wrapper.innerHTML),
            'no onmouseover survived: ' + wrapper.innerHTML
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: unclobbered cross-realm form root is still sanitized in-place',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          // Guard against false positives of the realm-safe probes: a foreign
          // form whose children do not shadow any inspected property must
          // not be reported as clobbered.
          var root = idoc.createElement('form');
          root.setAttribute('onmouseover', 'window.__hpcv_plain = 1');
          root.setAttribute('action', 'javascript:alert(1)');
          var input = idoc.createElement('input');
          input.setAttribute('name', 'username');
          root.appendChild(input);

          var clean = DOMPurify.sanitize(root, { IN_PLACE: true });

          assert.strictEqual(clean, root, 'root is returned in-place');
          assert.notOk(
            root.hasAttribute('onmouseover'),
            'onmouseover removed from foreign-realm root'
          );
          assert.notOk(
            root.hasAttribute('action'),
            'javascript: action removed from foreign-realm root'
          );
          assert.equal(
            root.getElementsByTagName('input').length,
            1,
            'harmless input child is kept'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: cross-realm <template>.content is walked and sanitized',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          var wrapper = idoc.createElement('div');
          var tpl = idoc.createElement('template');
          if (!tpl.content) {
            assert.ok(true, 'SKIP: foreign realm does not support <template>');
            return;
          }

          tpl.innerHTML =
            '<img src="x" onerror="window.__hpcv_tpl_xss = 1">' +
            '<script>window.__hpcv_tpl_xss = 2</script>';
          wrapper.appendChild(tpl);

          // Pre-fix `template.content instanceof DocumentFragment` failed for
          // the foreign-realm fragment, so its contents were never walked.
          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          var img = tpl.content.querySelector('img');
          assert.ok(img, 'template content was reached');
          assert.equal(
            img && img.getAttribute('onerror'),
            null,
            'onerror inside foreign-realm <template> must be stripped'
          );
          assert.equal(
            tpl.content.querySelectorAll('script').length,
            0,
            'script inside foreign-realm <template> must be removed'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: nested cross-realm <template>.content is walked and sanitized',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          var wrapper = idoc.createElement('div');
          var outer = idoc.createElement('template');
          if (!outer.content) {
            assert.ok(true, 'SKIP: foreign realm does not support <template>');
            return;
          }

          outer.innerHTML =
            '<template><img src="x" onerror="window.__hpcv_deep_xss = 1">' +
            '</template>';
          wrapper.appendChild(outer);

          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          var inner = outer.content.querySelector('template');
          assert.ok(inner && inner.content, 'nested template survived');
          var img = inner && inner.content.querySelector('img');
          assert.ok(img, 'nested template content was reached');
          assert.equal(
            img && img.getAttribute('onerror'),
            null,
            'onerror inside nested foreign-realm <template> must be stripped'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-hpcv-96wg-7vj8: cross-realm element with a forbidden namespace is removed',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          // _checkValidNamespace was gated behind `currentNode instanceof
          // Element` (parent realm). An allowed tag name in an unallowed
          // namespace, or an SVG element directly under HTML, slipped past.
          var bogusNs = 'urn:example:not-allowed';
          var svgNs = 'http://www.w3.org/2000/svg';
          var wrapper = idoc.createElement('div');
          wrapper.appendChild(idoc.createElementNS(bogusNs, 'div'));
          wrapper.appendChild(idoc.createElementNS(svgNs, 'a'));

          DOMPurify.sanitize(wrapper, { IN_PLACE: true });

          assert.equal(
            wrapper.getElementsByTagNameNS(bogusNs, '*').length,
            0,
            'foreign-realm element in an unallowed namespace must be removed'
          );
          assert.equal(
            wrapper.getElementsByTagNameNS(svgNs, '*').length,
            0,
            'foreign-realm SVG element directly under HTML must be removed'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    // ---------------------------------------------------------------------------
    // Hook-driven allowlist pollution (GHSA-76mc-f452-cxcm).
    //
    // Before this fix: The data.allowedTags / data.allowedAttributes
    // fields passed to uponSanitizeElement / uponSanitizeAttribute hooks were
    // direct references to the live ALLOWED_TAGS / ALLOWED_ATTR sets. When no
    // explicit cfg.ALLOWED_TAGS was supplied, that live set WAS the
    // module-level DEFAULT_ALLOWED_TAGS constant. A hook that wrote
    //     data.allowedTags['script'] = true
    // therefore wrote permanently into the default constant. Subsequent
    // sanitize calls — even after removeAllHooks() and clearConfig() —
    // inherited the widened defaults until the entire DOMPurify instance
    // was recreated.
    //
    // Fix: when any uponSanitize* hook is registered, the allowlist sets are
    // cloned for the duration of the call. The hook then mutates the clone,
    // preserving the documented in-call widening behavior (the test
    // "ensure that a hook can add allowed tags / attributes on the fly"
    // continues to pass), while the next default-cfg call rebinds to the
    // untouched default.
    // ---------------------------------------------------------------------------

    QUnit.module(
      'Hook-driven allowlist pollution (GHSA-76mc-f452-cxcm)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          // Fresh instance per test — the bug under test IS cross-call
          // pollution, so test isolation requires per-test instances.
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
        });

        QUnit.test(
          'baseline: <script> and onclick are stripped under default config',
          function (assert) {
            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'fresh default sanitize strips <script>'
            );
            assert.equal(
              purify.sanitize('<a onclick="alert(1)">x</a>'),
              '<a>x</a>',
              'fresh default sanitize strips onclick'
            );
          }
        );

        QUnit.test(
          'in-call widening via hook still works (documented behavior preserved)',
          function (assert) {
            // This mirrors the test "ensure that a hook can add allowed
            // tags / attributes on the fly" and asserts that the pollution
            // fix did not break the documented hook-widening API. The fix
            // preserves in-call widening by handing the hook a clone of the
            // default; the clone is mutated and used for the rest of the
            // iteration.
            purify.addHook('uponSanitizeElement', function (node, data) {
              if (data.tagName === 'is-custom') {
                data.allowedTags['is-custom'] = true;
              }
            });
            purify.addHook('uponSanitizeAttribute', function (node, data) {
              if (data.attrName === 'super-custom') {
                data.allowedAttributes['super-custom'] = true;
              }
            });

            var input =
              '<p>HE<is-custom super-custom="test">LLO</is-custom></p>';
            assert.equal(
              purify.sanitize(input),
              input,
              'guarded hook widens allowlist for matching element in-call'
            );
          }
        );

        QUnit.test(
          'unguarded element hook does not poison subsequent default-config calls',
          function (assert) {
            purify.addHook('uponSanitizeElement', function (node, data) {
              // The "leaky" pattern: unconditionally widen.
              data.allowedTags['script'] = true;
            });

            // First call: hook is active. In-call widening works (mirrors
            // the documented behavior), so script survives.
            assert.equal(
              purify.sanitize('<svg><script>1</script></svg>'),
              '<svg><script>1</script></svg>',
              'in-call widening still works while hook is registered'
            );

            purify.removeAllHooks();
            purify.clearConfig();

            // Second call after hook removal: the bug. Pre-fix, the module
            // default has been polluted and <script> still passes. Post-fix,
            // the default was never touched (only the per-call clone was)
            // and <script> is correctly stripped.
            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'default sanitize after element-hook removal strips <script>'
            );
          }
        );

        QUnit.test(
          'unguarded attribute hook does not poison subsequent default-config calls',
          function (assert) {
            purify.addHook('uponSanitizeAttribute', function (node, data) {
              data.allowedAttributes['onclick'] = true;
            });

            // In-call widening works.
            assert.ok(
              purify
                .sanitize('<a onclick="alert(1)">x</a>')
                .indexOf('onclick') !== -1,
              'in-call widening still works for attribute hook'
            );

            purify.removeAllHooks();
            purify.clearConfig();

            assert.equal(
              purify.sanitize('<a onclick="alert(1)">x</a>'),
              '<a>x</a>',
              'default sanitize after attr-hook removal strips onclick'
            );
          }
        );

        QUnit.test(
          'pollution does not cross instance boundaries',
          function (assert) {
            // Pollute the first instance.
            purify.addHook('uponSanitizeElement', function (node, data) {
              data.allowedTags['script'] = true;
            });
            purify.sanitize('<svg><script>alert(1)</script></svg>');

            // A separately-constructed instance must not inherit the
            // (now-fixed-or-not) state of the first instance.
            var freshInstance = DOMPurify(window);
            assert.equal(
              freshInstance.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'fresh DOMPurify instance must not inherit poisoned defaults'
            );
          }
        );

        QUnit.test(
          'read-only hook does not poison defaults',
          function (assert) {
            // Pure-read access to data.allowedTags is the safest hook
            // pattern and must continue to work. The fix's pre-clone is
            // harmless here — the hook reads from a clone, then the clone
            // is discarded at call end.
            var sawScriptKey;
            purify.addHook('uponSanitizeElement', function (node, data) {
              if (sawScriptKey === undefined) {
                sawScriptKey = 'script' in data.allowedTags;
              }
            });

            purify.sanitize('<div><span>hi</span></div>');

            assert.strictEqual(
              sawScriptKey,
              false,
              'hook sees default allowlist with script NOT included'
            );

            purify.removeAllHooks();
            purify.clearConfig();

            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'read-only hook does not poison defaults'
            );
          }
        );

        QUnit.test(
          'multiple polluting calls do not accumulate state in defaults',
          function (assert) {
            // Stress: many calls with a polluting hook, then check recovery.
            // Each call gets a fresh clone; the clones are discarded at call
            // end; module defaults stay clean.
            purify.addHook('uponSanitizeElement', function (node, data) {
              data.allowedTags['script'] = true;
              data.allowedTags['iframe'] = true;
              data.allowedTags['object'] = true;
            });

            for (var i = 0; i < 10; i++) {
              purify.sanitize('<div></div>');
            }

            purify.removeAllHooks();
            purify.clearConfig();

            assert.equal(
              purify.sanitize('<svg><script>1</script></svg>'),
              '<svg></svg>',
              'script still stripped after 10 polluting calls'
            );
            assert.equal(
              purify.sanitize('<iframe src="x"></iframe>'),
              '',
              'iframe still stripped after 10 polluting calls'
            );
            assert.equal(
              purify.sanitize('<object data="x"></object>'),
              '',
              'object still stripped after 10 polluting calls'
            );
          }
        );

        QUnit.test(
          'explicit cfg.ALLOWED_TAGS path is unaffected by hook mutation in other calls',
          function (assert) {
            // When cfg.ALLOWED_TAGS is supplied, ALLOWED_TAGS is already a
            // per-call fresh object (built via addToSet({}, ...)), not the
            // module default. Hooks mutating it can't pollute the default
            // even pre-fix. Asserting this explicitly catches a hypothetical
            // over-correction that breaks the explicit-cfg path.
            purify.addHook('uponSanitizeElement', function (node, data) {
              data.allowedTags['script'] = true;
            });

            // First call: explicit restrictive cfg, hook widens, script
            // survives in-call.
            var withCfg = purify.sanitize(
              '<svg><script>alert(1)</script></svg>',
              { ALLOWED_TAGS: ['svg'] }
            );
            assert.ok(
              withCfg.indexOf('<script>') !== -1,
              'explicit-cfg call respects in-call hook widening: ' + withCfg
            );

            purify.removeAllHooks();
            purify.clearConfig();

            // Default call afterwards must still be clean.
            assert.equal(
              purify.sanitize('<svg><script>alert(1)</script></svg>'),
              '<svg></svg>',
              'default-cfg call after explicit-cfg+hook is unaffected'
            );
          }
        );
      }
    );

    // ---------------------------------------------------------------------------
    // Residual DOM-clobbering surfaces (GHSA-76mc-f452-cxcm).
    //
    // HTMLFormElement has [LegacyOverrideBuiltIns], so a named descendant
    // shadows any prototype property read directly off the form:
    //   - <input name="nodeType"> makes form.nodeType return the input. The
    //     mXSS / PI / comment branches of _sanitizeElements compare
    //     currentNode.nodeType directly, so _isClobbered now compares the
    //     direct read against the cached Node.prototype.nodeType getter.
    //   - <input name="parentNode"> makes form.parentNode return the input.
    //     The KEEP_CONTENT branch used to fall back to currentNode.parentNode
    //     when the cached getter returned null (a parent-less IN_PLACE root),
    //     re-parenting the root's children into the attacker's named child.
    //     The fallback is gone; only the cached getters are used.
    // ---------------------------------------------------------------------------

    var _formClobbers76mc = function (name) {
      var form = document.createElement('form');
      var input = document.createElement('input');
      input.setAttribute('name', name);
      form.appendChild(input);
      return form[name] === input;
    };

    QUnit.module(
      'DOM clobbering via nodeType / parentNode (GHSA-76mc-f452-cxcm)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
        });

        QUnit.test(
          'form clobbered by <input name="nodeType"> is removed from string input',
          function (assert) {
            if (!_formClobbers76mc('nodeType')) {
              assert.ok(true, 'SKIP: no form clobbering in this engine');
              return;
            }

            assert.equal(
              purify.sanitize(
                '<form onsubmit=alert(1)><input onfocus=alert(2) name=nodeType>123</form>'
              ),
              '',
              'nodeType-clobbered form must be detected as clobbered and removed'
            );
          }
        );

        QUnit.test(
          'form clobbered by <input name="nodeType"> inside an IN_PLACE tree is removed',
          function (assert) {
            if (!_formClobbers76mc('nodeType')) {
              assert.ok(true, 'SKIP: no form clobbering in this engine');
              return;
            }

            var wrapper = document.createElement('div');
            var form = document.createElement('form');
            form.setAttribute('onmouseover', 'window.__rooted_76mc = 1');
            var clobber = document.createElement('input');
            clobber.setAttribute('name', 'nodeType');
            form.appendChild(clobber);
            wrapper.appendChild(form);

            purify.sanitize(wrapper, { IN_PLACE: true });

            assert.equal(
              wrapper.querySelectorAll('form').length,
              0,
              'nodeType-clobbered form must be removed from the IN_PLACE tree'
            );
          }
        );

        QUnit.test(
          'IN_PLACE root clobbered by <input name="nodeType"> throws',
          function (assert) {
            if (!_formClobbers76mc('nodeType')) {
              assert.ok(true, 'SKIP: no form clobbering in this engine');
              return;
            }

            var root = document.createElement('form');
            root.setAttribute('onmouseover', 'window.__rooted_76mc = 1');
            var clobber = document.createElement('input');
            clobber.setAttribute('name', 'nodeType');
            root.appendChild(clobber);

            assert.throws(
              function () {
                purify.sanitize(root, { IN_PLACE: true });
              },
              /clobbered/i,
              'nodeType-clobbered IN_PLACE root must throw'
            );
          }
        );

        QUnit.test(
          'unclobbered form is still kept (no false positive from the nodeType probe)',
          function (assert) {
            assert.equal(
              purify.sanitize(
                '<form onsubmit=alert(1)><input name=username>123</form>'
              ),
              '<form><input name="username">123</form>',
              'plain form survives sanitization'
            );
          }
        );

        QUnit.test(
          'KEEP_CONTENT does not re-parent children into a clobbered parentNode',
          function (assert) {
            if (!_formClobbers76mc('parentNode')) {
              assert.ok(true, 'SKIP: no form clobbering in this engine');
              return;
            }

            // A hook narrows the allowlist for the form, so the parent-less
            // IN_PLACE root reaches the KEEP_CONTENT branch. Its cached
            // parentNode is null; the old `|| currentNode.parentNode`
            // fallback then read the clobbered property and inserted clones
            // of the root's children into the attacker's named child.
            purify.addHook('uponSanitizeElement', function (node, data) {
              if (data.tagName === 'form') {
                delete data.allowedTags.form;
              }
            });

            var root = document.createElement('form');
            var clobber = document.createElement('input');
            clobber.setAttribute('name', 'parentNode');
            root.appendChild(clobber);
            var payload = document.createElement('b');
            payload.appendChild(document.createTextNode('kept'));
            root.appendChild(payload);

            purify.sanitize(root, { IN_PLACE: true });

            assert.equal(
              clobber.childNodes.length,
              0,
              'no clones were inserted into the clobbering named child'
            );
            assert.equal(
              root.querySelectorAll('b').length,
              1,
              'the root still holds exactly one copy of its content'
            );
          }
        );
      }
    );

    // ---------------------------------------------------------------------------
    // CVE-2026-49978 (GHSA-rp9w-3fw7-7cwq): an attached shadow root on an
    // element inside <template>.content was reached by no walk in IN_PLACE
    // mode, so its payload survived and fired once the template was
    // stamped. _sanitizeShadowDOM now inspects the shadowRoot of every
    // element it iterates and walks it recursively.
    //
    // Every shadow host below is moved into an inert template content
    // document BEFORE its shadow root gets markup, so the payloads never
    // load or run in the live test document.
    // ---------------------------------------------------------------------------

    QUnit.module(
      'IN_PLACE: shadow root inside template.content (CVE-2026-49978)',
      function (hooks) {
        var purify;
        hooks.beforeEach(function () {
          purify = DOMPurify(window);
        });
        hooks.afterEach(function () {
          purify.removeAllHooks();
          purify.clearConfig();
        });

        var supportsShadow = function () {
          var probe = document.createElement('div');
          if (typeof probe.attachShadow !== 'function') {
            return false;
          }

          try {
            probe.attachShadow({ mode: 'open' });
            return Boolean(probe.shadowRoot);
          } catch (_) {
            return false;
          }
        };

        var supportsClonableShadow = function () {
          if (!supportsShadow()) {
            return false;
          }

          var probe = document.createElement('div');
          try {
            probe.attachShadow({ mode: 'open', clonable: true });
          } catch (_) {
            return false;
          }

          // Engines that do not know `clonable` silently ignore it, so
          // probe the actual cloning behaviour.
          return Boolean(probe.cloneNode(true).shadowRoot);
        };

        var attachShadow = function (host, html, init) {
          var sr = host.attachShadow(init || { mode: 'open' });
          sr.innerHTML = html;
          return sr;
        };

        QUnit.test(
          'CVE-2026-49978: img onerror in shadow root inside template.content is stripped',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var tpl = document.createElement('template');
            var host = document.createElement('div');
            tpl.content.appendChild(host);
            attachShadow(host, '<img src=x onerror=alert(1)>');

            purify.sanitize(tpl, { IN_PLACE: true });

            var sr = tpl.content.firstChild.shadowRoot;
            assert.ok(sr, 'shadow root is still attached');
            var img = sr.querySelector('img');
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror inside shadow root inside template.content must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: javascript: link in shadow root inside template.content is neutralised',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var tpl = document.createElement('template');
            var host = document.createElement('div');
            tpl.content.appendChild(host);
            attachShadow(host, '<a href="javascript:alert(1)">click</a>');

            purify.sanitize(tpl, { IN_PLACE: true });

            var a = tpl.content.firstChild.shadowRoot.querySelector('a');
            assert.ok(a, 'benign <a> is kept');
            assert.equal(
              a.getAttribute('href'),
              null,
              'javascript: href inside shadow root inside template.content must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: script in shadow root inside template.content is removed',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var tpl = document.createElement('template');
            var host = document.createElement('div');
            tpl.content.appendChild(host);
            attachShadow(host, '<script>alert(1)</script><b>ok</b>');

            purify.sanitize(tpl, { IN_PLACE: true });

            var sr = tpl.content.firstChild.shadowRoot;
            assert.equal(
              sr.querySelectorAll('script').length,
              0,
              '<script> inside shadow root inside template.content must be removed'
            );
            assert.equal(
              sr.querySelectorAll('b').length,
              1,
              'benign content is kept'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: nested templates outer.content > inner.content > shadow root',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var outer = document.createElement('template');
            var inner = document.createElement('template');
            var host = document.createElement('div');
            outer.content.appendChild(inner);
            inner.content.appendChild(host);
            attachShadow(host, '<img src=x onerror=alert(1)>');

            purify.sanitize(outer, { IN_PLACE: true });

            var img = outer.content.firstChild.content.firstChild.shadowRoot.querySelector(
              'img'
            );
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in shadow root inside nested template content must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: wrapper element > template > shadow root',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var root = document.createElement('div');
            var tpl = document.createElement('template');
            var host = document.createElement('div');
            root.appendChild(tpl);
            tpl.content.appendChild(host);
            attachShadow(host, '<img src=x onerror=alert(1)>');

            purify.sanitize(root, { IN_PLACE: true });

            var img = root.firstChild.content.firstChild.shadowRoot.querySelector(
              'img'
            );
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in shadow root inside template inside wrapper must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: template > shadow root > template content is walked',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var tpl = document.createElement('template');
            var host = document.createElement('div');
            tpl.content.appendChild(host);
            attachShadow(
              host,
              '<template><img src=x onerror=alert(1)></template>'
            );

            purify.sanitize(tpl, { IN_PLACE: true });

            var innerTpl = tpl.content.firstChild.shadowRoot.querySelector(
              'template'
            );
            assert.ok(innerTpl, 'inner <template> is kept');
            var img = innerTpl.content.querySelector('img');
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror inside <template>.content inside a shadow root inside template.content must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: template > shadow root > template > shadow root (alternating descent)',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var tpl = document.createElement('template');
            var outerHost = document.createElement('div');
            tpl.content.appendChild(outerHost);
            var outerSr = attachShadow(outerHost, '<template></template>');
            var innerHost = document.createElement('div');
            outerSr.firstChild.content.appendChild(innerHost);
            attachShadow(innerHost, '<img src=x onerror=alert(1)>');

            purify.sanitize(tpl, { IN_PLACE: true });

            var innerSr =
              tpl.content.firstChild.shadowRoot.firstChild.content.firstChild
                .shadowRoot;
            assert.ok(innerSr, 'inner shadow root is still attached');
            var img = innerSr.querySelector('img');
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in deep template > shadow > template > shadow chain must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: shadow root nested in a shadow root inside template.content',
          function (assert) {
            if (!supportsShadow()) {
              assert.ok(true, 'SKIP: attachShadow not supported');
              return;
            }

            var tpl = document.createElement('template');
            var outerHost = document.createElement('div');
            tpl.content.appendChild(outerHost);
            var outerSr = attachShadow(outerHost, '<div></div>');
            attachShadow(outerSr.firstChild, '<img src=x onerror=alert(1)>');

            purify.sanitize(tpl, { IN_PLACE: true });

            var img = tpl.content.firstChild.shadowRoot.firstChild.shadowRoot.querySelector(
              'img'
            );
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror in shadow root nested in a shadow root inside template.content must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: clonable shadow root inside template.content does not survive stamping',
          function (assert) {
            if (!supportsClonableShadow()) {
              assert.ok(
                true,
                'SKIP: clonable shadow roots not supported in this engine'
              );
              return;
            }

            var tpl = document.createElement('template');
            var host = document.createElement('div');
            tpl.content.appendChild(host);
            attachShadow(host, '<img src=x onerror=alert(1)>', {
              mode: 'open',
              clonable: true,
            });

            purify.sanitize(tpl, { IN_PLACE: true });

            // The realistic exploitation path is stamping the template.
            // Clone inside the inert content document so nothing can fire.
            var stamped = tpl.content.cloneNode(true);
            var stampedSr = stamped.firstChild.shadowRoot;
            if (!stampedSr) {
              assert.ok(true, 'SKIP: clone carries no shadow root to stamp');
              return;
            }

            var img = stampedSr.querySelector('img');
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'onerror inside stamped clonable shadow root must be stripped'
            );
          }
        );

        QUnit.test(
          'CVE-2026-49978: clonable shadow root in nested template does not survive stamping',
          function (assert) {
            if (!supportsClonableShadow()) {
              assert.ok(
                true,
                'SKIP: clonable shadow roots not supported in this engine'
              );
              return;
            }

            var outer = document.createElement('template');
            var inner = document.createElement('template');
            var host = document.createElement('div');
            outer.content.appendChild(inner);
            inner.content.appendChild(host);
            attachShadow(host, '<img src=x onerror=alert(1)>', {
              mode: 'open',
              clonable: true,
            });

            purify.sanitize(outer, { IN_PLACE: true });

            var stamped = outer.content.cloneNode(true);
            var stampedSr = stamped.firstChild.content.firstChild.shadowRoot;
            if (!stampedSr) {
              assert.ok(true, 'SKIP: clone carries no shadow root to stamp');
              return;
            }

            var img = stampedSr.querySelector('img');
            assert.ok(img, 'benign <img> is kept');
            assert.equal(
              img.getAttribute('onerror'),
              null,
              'stamped img onerror stripped after deep-nested sanitize'
            );
          }
        );
      }
    );

    // ---------------------------------------------------------------------------
    // GHSA-x4vx-rjvf-j5p4 - IN_PLACE nodeName spoofing. A hostile live node
    // (handed over by a same-origin iframe / popup, or adopted via
    // document.adoptNode) can define an own `nodeName` property that shadows
    // the Node.prototype getter. The allowlist decision used to read the
    // instance property directly, so a real <script> reporting "DIV" was kept
    // and executed once the tree was attached to the document.
    // ---------------------------------------------------------------------------
    var _spoofNodeNameX4vx = function (node, spoofedName) {
      Object.defineProperty(node, 'nodeName', {
        value: spoofedName,
        configurable: true,
      });
      return node;
    };

    QUnit.test(
      'GHSA-x4vx-rjvf-j5p4: <script> spoofing nodeName "DIV" is removed on IN_PLACE',
      function (assert) {
        window.__x4vx_fired = 0;
        var host = document.createElement('div');
        var script = document.createElement('script');
        script.text = 'window.__x4vx_fired = 1;';
        _spoofNodeNameX4vx(script, 'DIV');
        host.appendChild(script);

        assert.equal(script.nodeName, 'DIV', 'spoof is in effect');

        var clean = DOMPurify.sanitize(host, { IN_PLACE: true });

        assert.strictEqual(clean, host, 'host is returned in-place');
        assert.equal(
          host.getElementsByTagName('script').length,
          0,
          'real <script> reporting nodeName "DIV" must be removed'
        );

        document.body.appendChild(host);
        document.body.removeChild(host);
        assert.equal(
          window.__x4vx_fired,
          0,
          'sanitized tree must not execute the payload once attached'
        );
      }
    );

    QUnit.test(
      'GHSA-x4vx-rjvf-j5p4: accessor-based nodeName spoof does not keep a <script>',
      function (assert) {
        var host = document.createElement('div');
        var script = document.createElement('script');
        script.text = 'window.__x4vx_accessor = 1;';
        Object.defineProperty(script, 'nodeName', {
          get: function () {
            return 'DIV';
          },
          configurable: true,
        });
        host.appendChild(script);

        DOMPurify.sanitize(host, { IN_PLACE: true });

        assert.equal(
          host.getElementsByTagName('script').length,
          0,
          'getter-spoofed <script> must be removed'
        );
      }
    );

    QUnit.test(
      'GHSA-x4vx-rjvf-j5p4: <a> spoofing nodeName "IMG" does not keep a data: href',
      function (assert) {
        var host = document.createElement('div');
        var anchor = document.createElement('a');
        anchor.setAttribute(
          'href',
          'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
        );
        _spoofNodeNameX4vx(anchor, 'IMG');
        host.appendChild(anchor);

        DOMPurify.sanitize(host, { IN_PLACE: true });

        var kept = host.getElementsByTagName('a');
        assert.equal(kept.length, 1, 'the <a> element itself is allowed');
        assert.notOk(
          kept[0].hasAttribute('href'),
          'data: href is only valid for data-URI tags, not for a spoofed <a>'
        );
      }
    );

    QUnit.test(
      'GHSA-x4vx-rjvf-j5p4: parent-less <script> root spoofing nodeName "DIV" throws on IN_PLACE',
      function (assert) {
        var script = document.createElement('script');
        script.text = 'window.__x4vx_root = 1;';
        _spoofNodeNameX4vx(script, 'DIV');

        // The main loop can not detach a parent-less root, so the spoofed
        // root must be refused by the pre-check.
        assert.throws(
          function () {
            DOMPurify.sanitize(script, { IN_PLACE: true });
          },
          /forbidden/i,
          'spoofed <script> root must be refused'
        );
      }
    );

    QUnit.test(
      'GHSA-x4vx-rjvf-j5p4: spoofed <script> from a same-origin iframe is removed on IN_PLACE',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc, iwin) {
          var host = idoc.createElement('div');
          var script = idoc.createElement('script');
          script.text = 'window.__x4vx_iframe = 1;';
          iwin.Object.defineProperty(script, 'nodeName', {
            value: 'DIV',
            configurable: true,
          });
          host.appendChild(script);

          DOMPurify.sanitize(host, { IN_PLACE: true });

          assert.equal(
            host.getElementsByTagName('script').length,
            0,
            'foreign-realm <script> reporting "DIV" must be removed'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );

    QUnit.test(
      'GHSA-x4vx-rjvf-j5p4: spoofed <script> adopted via document.adoptNode is removed on IN_PLACE',
      function (assert) {
        var ran = _withForeignRealmDocHpcv(function (idoc) {
          var host = idoc.createElement('div');
          var script = idoc.createElement('script');
          script.text = 'window.__x4vx_adopted = 1;';
          _spoofNodeNameX4vx(script, 'DIV');
          host.appendChild(script);

          var adopted = document.adoptNode(host);

          DOMPurify.sanitize(adopted, { IN_PLACE: true });

          assert.equal(
            adopted.getElementsByTagName('script').length,
            0,
            'adopted <script> reporting "DIV" must be removed'
          );
        });
        if (!ran) {
          assert.ok(true, 'SKIP: cannot construct a foreign-realm document');
        }
      }
    );
  };
});
