export default () => ({
  email: {
    senderEmail: process.env.SENDER_EMAIL,
    appUsername: process.env.APP_USERNAME,
    appPassword: process.env.APP_PASSWORD,
    mailtrap:{
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      username: process.env.MAILTRAP_USERNAME,
      password: process.env.MAILTRAP_PASSWORD
    }
  },
});
