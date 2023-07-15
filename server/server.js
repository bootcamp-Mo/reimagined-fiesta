import express from 'express';
import path from 'path';
import db from './config/connection';
import routes from './routes';
import { ApolloServer } from 'apollo-server-express';
import { typeDefs, resolvers } from './path-to-your-schema-and-resolvers';

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// if we're in production, serve client/build as static assets
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/build')));
}

// Create an Apollo Server and apply it as a middleware to the Express app
const server = new ApolloServer({
  typeDefs,
  resolvers,
});
server.applyMiddleware({ app, path: '/graphql' });

app.use(routes);

db.once('open', () => {
  app.listen(PORT, () => console.log(`🌍 Now listening on localhost:${PORT}`));
});
