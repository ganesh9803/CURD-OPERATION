# CURD-OPERATIN

Given an `index.js` file and a database file `Products.DB.db` consisting of five tables `users`, `Products`.

Write APIs to perform operations on the tables `user`, `products`, containing the following columns,

**Users Table**

| Column   | Type    |
| -------- | ------- |
| username | TEXT    |
| email    | TEXT    |
| password | TEXT    |
| role     | TEXT    |


**Products Table**

| Column              | Type    |
| ------------------- | ------- |
| `uniq_id`           | INTEGER |
| `title`             | TEXt    |
| `Description`       | Text    |
| `Inventory_count`   | INTEGER |



#### Sample Valid User Credentials

```
{
    "username": "rahul123",
    "password": "rahul@123"

}
```

<Section id="section1" >

### API 1

#### Path: `/register/`

#### Method: `POST`

**Request**

```
{
    "username": "rahul123",
    "email": "rahul@123.com",
    "password": "rahul@123",
    "role": "admin"
}
```

- **Scenario 1**

  - **Description**:

    If the username already exists

  - **Response**
    - **Status code**
      ```
      400
      ```
    - **Body**
      ```
      User already exists
      ```

- **Scenario 2**

  - **Description**:

    If the registrant provides a password with less than 6 characters

  - **Response**
    - **Status code**
      ```
      400
      ```
    - **Body**
      ```
      Password is too short
      ```

- **Scenario 3**

  - **Description**:

    Successful registration of the registrant

  - **Response**

    - **Status code**

      ```
      200
      ```

    - **Body**
      ```
      User created successfully
      ```

</Section>

<Section id="section2">

### API 2

#### Path: `/login/`

#### Method: `POST`

**Request**

```
{
  "username":"JoeBiden",
  "password":"biden@123"
}
```

- **Scenario 1**

  - **Description**:

    user not rgistered

  - **Response**
    - **Status code**
      ```
      400
      ```
    - **Body**
      ```
      Invalid user
      ```

- **Scenario 2**

  - **Description**:

    If the user provides an incorrect password

  - **Response**
    - **Status code**
      ```
      400
      ```
    - **Body**
      ```
      Invalid password
      ```

- **Scenario 3**

  - **Description**:

    Successful login of the user

  - **Response**

    Return the JWT Token

    ```
    {
      "jwtToken": "ak2284ns8Di32......"
    }
    ```

</Section>

<Section id="authToken">

### Authentication with JWT Token

Write a middleware to authenticate the JWT token.

- **Scenario 1**

  - **Description**:

    If the JWT token is not provided by the user or an invalid JWT token is provided

  - **Response**
    - **Status code**
      ```
      401
      ```
    - **Body**
      ```
      Invalid JWT Token
      ```

- **Scenario 2**
  - After successful verification of JWT token, proceed to next middleware or handler

</Section>

<Section id="section3">

### API 3

#### Path: `/products/`

#### Method: `GET`

#### Description:

Returns the all product details

#### Response

```
 [
   {
    "id": 2,
    "title": "Smartphone",
    "description": "Latest model smartphone",
    "inventory_count": 100
  },
   ...
 ]
```

</Section>

### API 10

#### Path: `/products/create`

#### Method: `POST`

#### Description:

Create a new product add in products table

#### Request

```
Product Created Successfully
```

#### Response

```
Created a Tweet
```

</Section>

<Section id="section11">

### API 11

#### Path: `/products/1`

#### Method: `DELETE`

- **Scenario 1**

  - **Description**:

    product deleted successfully


Use `npm install` to install the packages.

To run the code type the command in the terminal `npx nodemon index.js`

**Export the express instance using the default export syntax.**

**Use Common JS module syntax.**
