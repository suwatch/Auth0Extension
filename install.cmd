if not exist %HOME%\site\wwwroot\bin mkdir %HOME%\site\wwwroot\bin
call xcopy %HOME%\SiteExtensions\Auth0Extension\Auth0Module.dll %HOME%\site\wwwroot\bin /D /Y
call xcopy %HOME%\SiteExtensions\Auth0Extension\auth0info.cshtml %HOME%\site\wwwroot /D /Y
