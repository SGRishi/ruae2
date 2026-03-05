# Countdown Background Credits

The countdown page now uses a 200-image catalog sorted into background packs:

- `177` Unsplash images (`images.unsplash.com`)
- `23` 500px-hosted images (`iso.500px.com/wp-content/uploads/...`)

Pack generation and scoring logic live in `public/countdown/background-packs.js`, with pack options:

- `Classic nature`
- `Dark theme`
- `Light theme`
- `Nature theme`
- `Mixed (Unsplash + 500px)`

Licensing / attribution links:

- Unsplash license: https://unsplash.com/license
- 500px site: https://500px.com

The runtime background selector and rotation are implemented in `public/countdown/countdown.js`.
