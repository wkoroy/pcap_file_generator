### pcap_file_generator
Эта библиотека предназначена для генерации файлов  формата PCAP .

Функции:
### PCAPFILE * lpcap_create(char * file_path )
Эта функция создает  файл и возвращает либо NULL в случае ошибки, либо  указатель  на PCAPFILE

### int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds)
Эта функция для заполнения файла созданного через lpcap_create, возвращает 0 при ошибке . На вход ей поступают :
 1. PCAPFILE * f_pcp  - указатель на только что созданный файл
 2. ethernet_data_t * eth_data  - кадр данных
 3. uint32_t current_seconds  - временной сдвиг в секундах относительно  предыдущего кадра
 4. uint32_t current_u_seconds - временной сдвиг в микросекундах относительно  предыдущего кадра

### void lpcap_close_file( PCAPFILE * f_pcp )
Эта функция закрытия файла
На вход ей поступают :
 1. PCAPFILE * f_pcp  - указатель на открытый и запичсанный файл
## Welcome to GitHub Pages

You can use the [editor on GitHub](https://github.com/wkoroy/pcap_file_generator/edit/master/README.md) to maintain and preview the content for your website in Markdown files.

Whenever you commit to this repository, GitHub Pages will run [Jekyll](https://jekyllrb.com/) to rebuild the pages in your site, from the content in your Markdown files.

### Markdown

Markdown is a lightweight and easy-to-use syntax for styling your writing. It includes conventions for

```markdown
Syntax highlighted code block

# Header 1
## Header 2
### Header 3

- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/wkoroy/pcap_file_generator/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
