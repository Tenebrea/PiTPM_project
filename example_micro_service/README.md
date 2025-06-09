`python -m venv venv` - создать виртуальное окружение

`venv\Scripts\activate` - активировать его

Для каждого микросервиса рекомендуется своё виртуальное окружение. _Здесь для примера сделано одно_

`pip install "fastapi[standard]"` - установить бибилиотеку
`pip install aio_pika uvicorn jinja2` - установить бибилиотеки

---

Для запуска шлюза:

- `cd gateway`
- `fastapi dev main.py` -
- Разбор кода шлюза `gateway.md`

---

Для запуска микроерисов(на примере `course_service`)

- `cd course_service`
- python main.py
- `Разбор кода микросервиса micro.md`
