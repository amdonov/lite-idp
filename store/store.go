package store
import "github.com/garyburd/redigo/redis"
import "time"
import "encoding/json"

type Storer interface {
    Store(key, value interface{}, time int) error
    Retrieve(key interface{}, value interface{}) error
}

type storer struct {
    pool *redis.Pool
}

func (s *storer) Store(key, value interface{}, time int) error {
    conn := s.pool.Get()
    defer conn.Close()
    data, err := json.Marshal(value)
    if err!=nil {
        return err
    }
    conn.Do("SETEX", key, time, data)
    return nil
}

func (s *storer)Retrieve(key interface{}, value interface{}) error {
    conn := s.pool.Get()
    defer conn.Close()
    data, err := conn.Do("GET", key)
    if err!=nil {
        return err
    }
    return json.Unmarshal(data.([]byte), value)
}

func newPool(server string) *redis.Pool {
    return &redis.Pool{
        MaxIdle: 3,
        IdleTimeout: 240 * time.Second,
        Dial: func() (redis.Conn, error) {
            c, err := redis.Dial("tcp", server)
            if err != nil {
                return nil, err
            }
            return c, err
        },
        TestOnBorrow: func(c redis.Conn, t time.Time) error {
            _, err := c.Do("PING")
            return err
        },
    }
}

func New(address string) Storer {
    return &storer{newPool(address)}
}