FROM node
WORKDIR /app

COPY package.json .
RUN npm i

COPY . .

EXPOSE 7216
CMD ["npm", "run", "dev"]
