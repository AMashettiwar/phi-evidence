# Third-party files used as test data

Real, unmodified library files that ship on real websites. `fixtures/build_realsite.py`
copies them into the realistic hospital site as its vendor assets, so the false-alarm
check reads code that nobody on this project wrote. Each keeps its own licence beside it
(`<file>.LICENSE.txt`); all are MIT licensed.

| File | Package |
|---|---|
| `vue.global.prod.js` | vue 3.5.39 |
| `react-dom.production.min.js` | react-dom 18.3.1 |
| `moment.min.js` | moment |
| `lodash.min.js` | lodash |
| `fontawesome.all.min.css` | @fortawesome/fontawesome-free (CSS is MIT; icons CC BY 4.0) |
| `shadcn.tailwind.css` | shadcn |
| `js-yaml.umd.min.js.map` | js-yaml (a source map with `sourcesContent`) |
