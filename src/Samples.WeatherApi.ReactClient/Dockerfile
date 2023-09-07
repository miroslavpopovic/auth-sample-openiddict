FROM node:20.3.0
WORKDIR /app

COPY package.json .
RUN npm i

COPY . .

EXPOSE 7216
CMD ["npm", "run", "dev"]
