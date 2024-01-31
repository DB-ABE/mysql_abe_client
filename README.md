# mysql_abe_client

命令示例：
```sql
insert into company.share0(title,data) values('first', abe_enc('this is the first data', 'attr1'));
select title, abe_dec(data) from company.share0 where title='first';
```

更新abe密钥：
```bash
show current_abe_key;
```