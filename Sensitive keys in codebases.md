# Sensitive keys in codebases

> Developers tend to commit sensitive information to version control systems. As we are moving towards CI/CD and GitOps systems, we tend to forgot identifying sensitive information in code and commits. Let’s see if we can find something cool here!

#### To get started with the scenario, navigate to http://127.0.0.1:1230

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration

For the first scenario, I started with an Nmap scan of port 1230 on the Goat server.

Browsing the web page revealed how the code service was built:

<img width="1315" height="239" alt="image" src="https://github.com/user-attachments/assets/a04591d4-a5ca-49d6-a34f-66cf993e6134" />

I then performed an `nmap` scan, but it did not reveal any open services:

<img width="1113" height="821" alt="image" src="https://github.com/user-attachments/assets/b2c09104-9b91-4da7-8cbe-a75943370361" />

### Fuzzing:

When the `nmap` scan did not reveal anything, I tried fuzzing the application by enumerating subdirectories. I used `dirsearch` to check for available subdirectories:

<img width="481" height="250" alt="image" src="https://github.com/user-attachments/assets/dea9f6f5-22a3-429b-a7fa-f74e9d26b15f" />

The scan revealed a "**.git**" directory, indicating that a Git repository is present in the application.

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Git enumeration

Because fuzzing revealed the presence of a **.git** directory, I used the tool `git-dumper` to create a local folder containing the repository structure.

```
git-dumper http://k8:1230/.git 1230_git
```

Running the command above saved the repository data into a local folder named `1230_git`.

<img width="752" height="558" alt="image" src="https://github.com/user-attachments/assets/d5f5b617-3b30-4901-bab1-ab0572d8ccd6" />

After the folder was created, I performed further enumeration by inspecting the Git history. I listed the commit logs with:

```
git log
```

<img width="829" height="639" alt="image" src="https://github.com/user-attachments/assets/6f5e8c6d-ad53-4f0d-ae30-8ae4193bdb1d" />

With the commit history available, I examined the changes introduced in each commit to look for sensitive information. In one specific commit I found that the .env file contained the flag. I viewed that commit with:

```
git show d7c173ad183c574109cd5c4c648ffe551755b576
```

<img width="552" height="295" alt="image" src="https://github.com/user-attachments/assets/6908d432-85fe-4718-a03f-0d00993a4585" />

The .env content in that commit contained the flag value, which confirmed that the repository included sensitive configuration data.
