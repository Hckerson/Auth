export default () => ({
  app: {
    port: process.env.PORT,
    auth: {
      tekcify: {
        callback: process.env.TEKCIFY_CALLBACK_URL,
        id: process.env.TEKCIFY_CLIENT_ID,
        secret: process.env.TEKCIFY_CLIENT_SECRET,
      },
      github: {
        callback: process.env.GITHUB_CALLBACK_URL,
        id: process.env.GITHUB_CLIENT_ID,
        secret: process.env.GITHUB_CLIENT_SECRET,
      },
      google: {
        callback: process.env.GOOGLE_CALLBACK_URL,
        id: process.env.GOOGLE_CLIENT_ID,
        secret: process.env.GOOGLE_CLIENT_SECRET,
      },
      authorizationUrl: process.env.AUTHORIZATION_URL,
      tokenUrl: process.env.TOKEN_URL,
    },
    ipKey: process.env.IP_API_KEY,
  },
});
