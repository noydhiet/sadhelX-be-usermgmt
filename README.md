# sadhelX-be-usermgmt
Specific repository for BE User management consist of Login, Registration, Forget Password
=======


# sadhelx-be-usermgmt

## Description

- ###### `/signup`: creating a new user

- ###### `/login`: user login

- ###### `/refresh-token` : refresh access token

- ###### `/get-password-reset-code`:  get code for password reset

- ###### `/password-reset`:  update new password

- ###### `/verify/password-reset`:  verify password reset code

- ###### `/verify/mail`: verify email after registration

- ###### `/check-username` :  check username availabilty

- ###### `/check-email`:  check email availability

- ###### `/avatar-upload:` to upload user avatar

- ###### `/avatar-storage:` to get image user avatar

  



## Status

### Ready

- /login
- /signup
- /check-username
- /check-email
- /get-password-reset
- /verify/password-reset
- /verify/mail
- /refresh-token
- /password-reset
- /avatar-upload
- /avatar-storage





### On-Going

None

### Not Implemented Yet

None



## Response Default Format

**Response body :**

- status - `boolean`
- msg - `string`
- data - `interface`



## Implementation

- ### **GET `/avatar-storage/{image_file}`**

- ### **GET `/check-username/{username}`**

  - #### **Response**

    - #### **true :**

      ```json
      {
      	"status": "true",
      	"msg": "User available"
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "User has already been taken"
      }
      ```





---

- ### **GET `/check-email/{email}`**

  - #### **Response**

    - #### **true :**

      ```json
      {
      	"status": "true",
      	"msg": "Email available"
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "Email has already been taken"
      }
      ```



---

- ### **POST `/signup`**

  - #### Request

    - #### **Header**

    - #### **Body**

      ```json
      {
          "username":"username4", 		// required
          "email":"email4", 				// required
          "firstname":"this firsname",
          "lastname":"this lastname",
          "password":"password", 			// required
          "phonenumber":"008070898742"
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
          "status": "true",
          "msg": "Success creating user"
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "Some msg error"
      }
      ```



---

- ### **POST `/login`**

  - #### Request

    - #### **Header**

    - #### **Body**

      ```json
      {
          "identity": "someemail@email.com",
          "password": "somepassword"    
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
      	"status": "true",
      	"msg": "Login successfull",
          "data": {
              "user": {
                  "user_id": "123414134",
                  "username": "usersadhelx1",
                  "email": "usersadhelx1@gmail.com"
              },
              "token": {
                  "token_access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySUQiOjMyMTg4Mzg2NDYsIktleVR5cGUiOiJhY2Nlc3MiLCJleHAiOjE2MTMwMzg1MDEsImlzcyI6InNhZGxleC5hdXRoLnNlcnZpY2UifQ",
                  "token_refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySUQiOjMyMTg4Mzg2NDYsIkN1c3RvbUtleSI6IjE3MTcwYzFiZWIwZWUzY2EzNWNjMmY1MWQ4NTdmYTVjYmIwYTNhY2VmODRlOTg3NDc3NDA0YzM0OTFiNWI4ODgiLCJLZXlUeXBlIjoicmVmcmVzaCIsImlzcyI6InNhZGxleC5hdXRoLnNlcnZpY2UifQ.a3uFdrFINLj27mbyQWyBc564VNw96y8qXvWDhoz_eWI"    
              }
          }
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```



---

- ### **POST `/refresh-token`**

  - #### Request

    - #### **Header**

      - ###### Authorization		Bearer \<refresh_token\>

    - #### **Body**

      ```json
      {
          "identity": "someemail@email.com", 
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
      	"status": "true",
      	"msg": "Access token successfull generated",
          "data": {
              "token": {
                  "token_access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVc2VySUQiOjMyMTg4Mzg2NDYsIktleVR5cGUiOiJhY2Nlc3MiLCJleHAiOjE2MTMwMzg1MDEsImlzcyI6InNhZGxleC5hdXRoLnNlcnZpY2UifQ"
              }
          }
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```



---

- ### **POST `/get-password-reset-code`**

  - #### Request

    - #### **Header**

    - #### **Body**

      ```json
      {
          "identity": "someemail@email.com", 
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
      	"status": "true",
      	"msg": "Password reset code has been sent to email",
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```



---

- ### **POST `/verify/password-reset`**

  - #### Request

    - #### **Header**

    - #### **Body**

      ```json
      {
          "identity": "someemail@email.com", 
          "code": "ASDF"
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
          "status": true,
          "msg": "Password reset code verified",
          "data": {
              "code": "CKTO"
      }
      
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```



---

- ### **POST `/verify/mail`**

  - #### Request

    - #### **Header**

    - #### **Body**

      ```json
      {
          "identity": "someemail@email.com", 
          "code": "ASDF"
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
      	"status": "true",
      	"msg": "User email verified",
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```





---

- ### PUT `/reset-password`

  - #### Request

    - #### **Header**

    - #### **Body**

      ```
      {
          "identity": "purnasatria@gmail.com",
          "password": "passwordbaru",
          "password_re": "passwordbaru",
          "code":"CKTO"
      }
      ```

      

  - #### **Response**

    - #### **true :**

      ```json
      {
          "status": true,
          "msg": "Password has been updated"
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```



---

- ### PUT `/avatar-upload`

  - #### Request

    - #### **Header**

    - #### **Body**

      Multipart-Form

      - identity: **purnasatria@gmail.com**
      - avatar: **image file**

      

  - #### **Response**

    - #### **true :**

      ```json
      {
          "status": true,
          "msg": "Avatar has been saved"
      }
      ```

    - #### **error/ false :**

      ```json
      {
          "status": "false",
      	"msg": "some msg error"
      }
      ```




## Further Development

- Implement more proper OTP mehod
- Implement deeplink for email confirmation
- Use 3rd party provider for email notification, such as Sendgrid
- Define user validation

