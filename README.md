
# Rails Devise JWT Implementation


## Fast_jsonapi
A lightning fast JSON:API serializer for Ruby Objects. It is better in performance compared to Active Model Serializer.

## Devise and JWT

Devise-jwt is a devise extension which uses JSON Web Tokens(JWT) for user authentication. With JSON Web Tokens (JWT), rather than using a cookie, a token is added to the request headers themselves (rather than stored/retrieved as a cookie). This isn’t performed automatically by the browser (as with cookies), but typically will be handled by a front-end framework as part of an AJAX call.

## Create a new Rails API app

In this step, We need to create a rails application with api_only mode with optional database params(If you want to change).

```
$ rails new rails-jwt-tutorial -–api -–database=postgresql -T
```

Here, I have created a rails 6 application using postgresql (Default SQLite).
(Note: If you are using postgresql then you have to setup database.yml)

## Configure Rack Middleware

As this is an API Only application, we have to handle ajax requests. So for that, we have to Rack Middleware for handling Cross-Origin Resource Sharing (CORS)

To do that, Just uncomment the

```
gem 'rack-cors'
```

line from your generated Gemfile. And uncomment the contents of `config/initialzers/cors.rb` the following lines to application.rb, adding an expose option in the process:

```rb
# config/initializers/cors.rb
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins '*'
    resource(
     '*',
     headers: :any,
     expose: ['access-token', 'expiry', 'token-type', 'Authorization'],
     methods: [:get, :patch, :put, :delete, :post, :options, :show]
    )
  end
end
```

Here, we can see that there should be an "Authorization" header exposed which will be used to dispatch and receive JWT tokens in Auth headers.

## Add the needed Gems

Here, we are going to add gem like ‘devise’ and ‘devise-jwt’ for authentication and the dispatch and revocation of JWT tokens and ‘fast_jsonapi’ gem for json response.

```rb
gem 'devise'
gem 'devise-jwt'
gem 'fast_jsonapi'
```

Then, do

```bash
bundle install
```

## Configure devise

By running the following command to run a generator

```
$ rails generate devise:install
```

It is important to set our navigational formats to empty in the generated devise.rb by uncommenting and modifying the following line since it’s an api only app.

```
config.navigational_formats = []
```

Also, add the following line to config/environments/development.rb

```
config.action_mailer.default_url_options = { host: 'localhost', port: 3000 }
```

## Create User model

You can create a devise model to represent a user. It can be named as anything. So, I’m gonna be going ahead with User. Run the following command to create User model.

```
$ rails generate devise User
```

Then run migrations using,

```
$ rails db:create
$ rails db:migrate
```

## Create devise controllers and routes

We need to create two controllers (sessions, registrations) to handle sign ups and sign ins.

```
rails g devise:controllers users -c sessions registrations
```

specify that they will be responding to JSON requests. The files will look like this:

```rb
class Users::SessionsController < Devise::SessionsController
  respond_to :json
end
```

```rb
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json
end
```

Then, add the routes aliases to override default routes provided by devise in the routes.rb

```rb
Rails.application.routes.draw do
  devise_for :users, path: '', path_names: {
    sign_in: 'login',
    sign_out: 'logout',
    registration: 'signup'
  },
  controllers: {
    sessions: 'users/sessions',
    registrations: 'users/registrations'
  }
end
```

## Configure devise-jwt

Add the following lines to devise.rb

```rb
config.jwt do |jwt|
    jwt.secret = Rails.application.credentials.fetch(:secret_key_base)
    jwt.dispatch_requests = [
      ['POST', %r{^/login$}]
    ]
    jwt.revocation_requests = [
      ['DELETE', %r{^/logout$}]
    ]
    jwt.expiration_time = 30.minutes.to_i
end
```

Here, we are just specifying that on every post request to login call, append JWT token to Authorization header as “Bearer” + token when there’s a successful response sent back and on a delete call to logout endpoint, the token should be revoked.

The `jwt.expiration_time` sets the expiration time for the generated token. In this example, it’s 30 minutes.

## Set up a revocation strategy

Revocation of tokens is an important security concern. The `devise-jwt` gme comes with three revocation strategies out of the box. You can read more about them in this [blog post on token recovation strategies](http://waiting-for-dev.github.io/blog/2017/01/24/jwt_revocation_strategies/).

For now, we'll be going with the one they recommended with is to store a single valid user attached token with the user record in the users table.

Here, the model class acts itself as the revocation strategy. It needs a new string column with name `jti` to be added to the user. `jti` stands for JWT ID, and it is a standard claim meant to uniquely identify a token.

It works like the following:

- When a token is dispatched for a user, the `jti` claim is taken from the `jti` column in the model (which has been initialized when the record has been created).
- At every authenticated action, the incoming token `jti` claim is matched against the `jti` column for that user. The authentication only succeeds if they are the same.
- When the user requests to sign out its `jti` column changes, so that provided token won't be valid anymore.

In order to use it, you need to add the `jti` column to the user model. So, you have to set something like the following in a migration:

```ruby
def change
  add_column :users, :jti, :string, null: false
  add_index :users, :jti, unique: true
  # If you already have user records, you will need to initialize its `jti` column before setting it to not nullable. Your migration will look this way:
  # add_column :users, :jti, :string
  # User.all.each { |user| user.update_column(:jti, SecureRandom.uuid) }
  # change_column_null :users, :jti, false
  # add_index :users, :jti, unique: true
end
```

To add this, we can run

```
rails g migration addJtiToUsers jti:string:index:unique
```

And then make sure to add `null: false` to the `add_column` line and `unique: true` to the `add_index` line

**Important:** You are encouraged to set a unique index in the `jti` column. This way we can be sure at the database level that there aren't two valid tokens with same `jti` at the same time.

Then, you have to add the strategy to the model class and configure it accordingly:

```ruby
class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::JTIMatcher

  devise :database_authenticatable, :registerable, :validatable,
         :jwt_authenticatable, jwt_revocation_strategy: self
end
```

Be aware that this strategy makes uses of `jwt_payload` method in the user model, so if you need to use it don't forget to call `super`:

```ruby
def jwt_payload
  super.merge('foo' => 'bar')
end
```

In our case, we won't be needing to interact with the jwt_payload directly, so we can move on for now. Next, we'll run migrations using

```bash
rails db:migrate
```

## Add respond_with using fast_jsonapi method

As we already added the `fast_jsonapi` gem, we can generate a serializer to configure the json format we'll want to send to our front end API.

```
$ rails generate serializer user id email created_at
```

It will create a serializer with a predefined structure. Now, we have to add the attributes we want to include as a user response. So, we'll add the user's id, email and created_at. So the final version of user_serializer.rb looks like this:

```rb
class UserSerializer
  include FastJsonapi::ObjectSerializer
  attributes :id, :email, :created_at
end
```

We can access serializer data for single record by,

```rb
UserSerializer.new(resource).serializable_hash[:data][:attributes]
And multiple records by,
UserSerializer.new(resource).serializable_hash[:data].map{|data| data[:attributes]}
```

Now, we have to tell devise to communicate through JSON by adding these methods in the `RegistrationsController` and `SessionsController`

```rb
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    if resource.persisted?
      render json: {
        status: {code: 200, message: 'Signed up sucessfully.'},
        data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
      }
    else
      render json: {
        status: {message: "User couldn't be created successfully. #{resource.errors.full_messages.to_sentence}"}
      }, status: :unprocessable_entity
    end
  end
end

class Users::SessionsController < Devise::SessionsController
  respond_to :json
  private

  def respond_with(resource, _opts = {})
    render json: {
      status: {code: 200, message: 'Logged in sucessfully.'},
      data: UserSerializer.new(resource).serializable_hash[:data][:attributes]
    }, status: :ok
  end

  def respond_to_on_destroy
    if current_user
      render json: {
        status: 200,
        message: "logged out successfully"
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end
end
```

Remember, you can use the attribute method in a serializer to add a property to the JSON response based on an expression you return from a block that has access to the object you're serializing. For example, you can modify the column name and data format by overwrite attribute:

```rb
attribute :created_date do |user|
       user && user.created_at.strftime('%d/%m/%Y')
end
```

Here, we're adding a created_date attribute that will reformat the user's created_at value in the one we specify.

Here you can get [detailed information on fast_jsonapi](https://github.com/Netflix/fast_jsonapi).


## Sanity Check: Try it out in Postman!
To start up our local dev server on port 4000, we’ll want to change some default configuration so we don’t need to add a flag every time.

```rb
# in config/puma.rb
port ENV.fetch("PORT") { 3000 }
```
replace with:

```rb
port ENV.fetch("PORT") { 4000 }
```
Now we can run

```b
rails s
```
And try out a POST request to ‘/signup’ with the following body:
```rb
{
  "user": {
    "email": "test@test.com",
    "password": "password"
  }
}
```

When we try this we should see a response that looks like this:
```rb
{
  "status": {
    "code": 200,
    "message": "Signed up sucessfully."
  },
  "data": {
    "id": 1,
    "email": "test@test.com",
    "created_at": "2023-01-27T03:51:52.255Z",
    "created_date": "01/27/2023"
  }
}
```
But the first time I did it, I actually got an error that looked something like this:
```b
Completed 500 Internal Server Error in 301ms (ActiveRecord: 7.6ms | Allocations: 13211)


  
ActionDispatch::Request::Session::DisabledSessionError 
(Your application has sessions disabled. To write to the 
session you must first configure a session store):
```

This is a bit frustrating, as in API only mode we’re not going to be using session cookies. This is an unfixed bug in Devise with Rails 7 at the moment. There’s an issue on the Devise-JWT repo that discusses this problem including a few fixes. My pick was to go with a fix that is focused on giving devise a fake rack session hash that has enabled? set to false to avoid the error that it would otherwise raise.

To implement the fix, create a new file in controllers/concerns:
```rb
# app/controllers/concerns/rack_session_fix.rb
module RackSessionFix
  extend ActiveSupport::Concern
  class FakeRackSession < Hash
    def enabled?
      false
    end
  end
  included do
    before_action :set_fake_rack_session_for_devise
    private
    def set_fake_rack_session_for_devise
      request.env['rack.session'] ||= FakeRackSession.new
    end
  end
end
```
And then, at the top of both our controllers:

```rb
class Users::SessionsController < Devise::SessionsController
  include RackSessionFix
  ...
end


class Users::RegistrationsController < Devise::RegistrationsController
  include RackSessionFix
  ...
end
```
Now, we’ll be able to signup and login.

## Adding a '/current_user' endpoint

We'll probably want to create an endpoint that will return the current user given a valid JWT in the headers. This will be useful in our frontend code to be able to recognize if we have an active session before visiting a client side route that shouldn't be accessible without an active session.

```bash
rails g controller current_user index
```

And then in `config/routes.rb` find this line:

```rb
get 'current_user/index'
```
and replace it with
```rb
get '/current_user', to: 'current_user#index'
```
Now, fill in the `CurrentUserController` so it looks like this:

```rb
class CurrentUserController < ApplicationController
  before_action :authenticate_user!
  def index
    render json: current_user, status: :ok
  end
end
```
Adding the `before_action :authenticate_user` will ensure that we only see a 200 response if we have a valid JWT in the headers. If we don't this endpoint should return a `401` status code.

## API Testing

Copy and past in the browser console. If everything works fine, you should get a token bearer.

```b
fetch("http://localhost:4000/signup", {
  method: "post",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    user: {
      email: "test@test0.com",
      password: "password",
    },
  }),
})
  .then((res) => {
    if (res.ok) {
      console.log(res.headers.get("Authorization"));
      localStorage.setItem("token", res.headers.get("Authorization"));
      return res.json();
    } else {
      throw new Error(res);
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
  ```
  You can test if users are logged in when they only have authorization to view certain pages of the webapp.
  
  for instance you can add a books to our app and only if users are logged in that they can see the books.
  
  ```b
  rails g resource Book author title
  ```
We can then make our book controller to look like this:

```
class BookController < ApplicationController
  before_action :authenticate_user!
  def index
    render json: {
      message: "This is a private message for #{current_user.email} you should only see if you've got a correct token"
    }
  end
end
```
And now, to test this out in the browser, you can run this:
But note that, without our JWT, the request will be unauthorized if we have the `before_action :authenticate_user!` in our controller. So, now we can add the token in the header.

```rb
fetch("http://localhost:3000/private/test", {
  headers: {
    "Content-Type": "application/json",
    Authorization: localStorage.getItem("token"),
  },
})
  .then((res) => {
    if (res.ok) {
      return res.json();
    } else if (res.status == "401") {
      throw new Error("Unauthorized Request. Must be signed in.");
    }
  })
  .then((json) => console.dir(json))
  .catch((err) => console.error(err));
  ```
