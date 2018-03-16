## Cloudentity Web Auth

Cloudentity Web Auth client for Javascript Single Page Apps.

## Import

### Script tag

    <script src="cloudentity-web-auth.js"></script>

### Node.js style

    const CloudentityWebAuth = require('cloudentity-web-auth');

### ES6 import

    import CloudentityWebAuth from 'cloudentity-web-auth';
    
    
## Usage

1. First – create and configure CloudentityWebAuth:

        var cloudentity = new CloudentityWebAuth({
            domain: 'your-cloudentity-domain',
            clientId: 'your-oauth-client-id',
            redirectUri: window.location.href,
            scopes: ['email']
        }); 
    
2. To check if there's an OAuth response in URL hash and parse it:

        cloudentity.getAuth().then(
          function (authResponse) { 
            // use oauth data, clean hash string, etc.
          },
          
          finction (errorResponse) { 
            // we're not authorized 
          }
        );

3. If not (e.g. this is the initial app load), to initialize OAuth2 implicit flow:

        cloudentity.authorize(); // redirects to authorization service